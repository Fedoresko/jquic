/*
 * Copyright 2026 Fedor Malyshev
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jquic.http3.qpack;

import org.jquic.quic.struct.TimeoutHeap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class QpackEncoder implements Encoder {
    private static final Logger logger = LoggerFactory.getLogger(QpackEncoder.class);

    public static final int DEFAULT_MAX_TABLE_CAPACITY = 4096;
    public static final int DEFAULT_INDEXING_THRESHOLD = 512;
    public static final int EVICTION_THRESHOLD = 4;
    private static final int HEADER_BLOCK_PREFIX_SIZE = 20;
    private static final int INT_MAX_ENCODED_SIZE = 10;
    private static final int INITIAL_HEADER_BLOCK_SIZE = 8192;

    private static final int VARINT_7BIT_MASK = 0x7F;
    private static final int VARINT_CONTINUATION_BIT = 0x80;
    private static final int VARINT_SHIFT = 7;
    private static final int VARINT_MAX_SINGLE_BYTE = 128;

    private static final int DELTA_BASE_SIGN_BIT = 0x80;

    private static final int INDEXED_PREFIX = 0x80;
    private static final int INDEXED_STATIC_BIT = 0x40;
    private static final int INDEXED_PREFIX_BITS = 6;
    private static final int INDEXED_POST_BASE_PREFIX = 0x10;
    private static final int INDEXED_POST_BASE_PREFIX_BITS = 4;
    private static final int LITERAL_WITH_NAME_REF_PREFIX = 0x40;
    private static final int LITERAL_WITH_NAME_REF_PREFIX_BITS = 4;
    private static final int LITERAL_WITHOUT_NAME_REF_PREFIX = 0x20;
    private static final int LITERAL_WITHOUT_NAME_REF_PREFIX_BITS = 3;
    private static final int LITERAL_NAME_REF_STATIC_BIT = 0x10;

    private static final int ENCODER_INSERT_NAME_REF_PREFIX = 0x80;
    private static final int ENCODER_INSERT_NAME_REF_PREFIX_BITS = 6;
    private static final int ENCODER_INSERT_STATIC_BIT = 0x40;
    private static final int ENCODER_INSERT_LITERAL_NAME_PREFIX = 0x40;
    private static final int ENCODER_INSERT_LITERAL_NAME_PREFIX_BITS = 5;
    private static final int ENCODER_DUPLICATE_PREFIX = 0x00;
    private static final int ENCODER_DUPLICATE_PREFIX_BITS = 5;
    private static final int ENCODER_CAPACITY_PREFIX = 0x20;
    private static final int ENCODER_CAPACITY_PREFIX_BITS = 5;

    private static final int STRING_LENGTH_PREFIX_BITS = 7;
    private static final int RIC_PREFIX_BITS = 8;
    private static final int DELTA_BASE_PREFIX_BITS = 7;

    private final DataOutputStream encoderOutputStream;
    protected final QpackDynamicTable dynamicTable = new QpackDynamicTable();
    private static final Map<String, Integer> NAME_TO_INDEX = new HashMap<>();
    private static final Map<String, Map<String, Integer>> FULL_TO_INDEX = new HashMap<>();

    private long knownReceivedCount = 0;
    private final int indexingThreshold;
    private long maxPeerBlockedStreams = 0;
    private long blockedCount = 0;
    private final Map<Long, StreamRicEntry> streamRicEntries = new HashMap<>();
    private final TimeoutHeap<StreamRicEntry> ricHeap = new TimeoutHeap<>(StreamRicEntry.class);

    private static class StreamRicEntry implements TimeoutHeap.Entry {
        final long streamId;
        long maxRicNeeded;
        int heapIndex = -1;

        StreamRicEntry(long streamId) {
            this.streamId = streamId;
        }

        @Override public int getTimeoutHeapIndex() { return heapIndex; }
        @Override public void setTimeoutHeapIndex(int idx) { this.heapIndex = idx; }
        @Override public long getTimeoutTimestamp() { return maxRicNeeded; }
    }

    static {
        for (int i = 0; i < QpackStaticTable.TABLE.size(); i++) {
            QpackStaticTable.Entry entry = QpackStaticTable.TABLE.get(i);
            NAME_TO_INDEX.putIfAbsent(entry.name(), i);
            FULL_TO_INDEX.computeIfAbsent(entry.name(), _ -> new HashMap<>()).putIfAbsent(entry.value(), i);
        }
    }

    public QpackEncoder(DataOutputStream encoderOutputStream) {
        this(encoderOutputStream, DEFAULT_MAX_TABLE_CAPACITY, DEFAULT_INDEXING_THRESHOLD);
    }

    public QpackEncoder(DataOutputStream encoderOutputStream, long maxCapacity, int indexingThreshold) {
        this.encoderOutputStream = encoderOutputStream;
        this.indexingThreshold = indexingThreshold;
        dynamicTable.setCapacity(maxCapacity);
    }

    @Override
    public ByteBuffer encodeHeaders(long streamId, List<Header> headers) throws IOException {
        long ricBefore = dynamicTable.getInsertCount();
        long maxRicNeeded = 0;

        ByteBuffer headerBlock = ByteBuffer.allocate(INITIAL_HEADER_BLOCK_SIZE);
        for (Header header : headers) {
            // Check Static Table
            Map<String, Integer> staticValues = FULL_TO_INDEX.get(header.name());
            Integer staticFullIndex = (staticValues != null) ? staticValues.get(header.value()) : null;

            if (staticFullIndex != null) {
                // Indexed Header Field (Section 4.5.2)
                // 1Txxxxxx, T=1 (static)
                writePrefixInt(headerBlock, INDEXED_PREFIX | INDEXED_STATIC_BIT, INDEXED_PREFIX_BITS, staticFullIndex);
                continue;
            }

            // Check Dynamic Table
            Integer dynamicFullIndex = findInDynamicTable(header.name(), header.value());
            if (dynamicFullIndex != null) {
                // RFC 9204 Section 2.1.1: Duplicate an entry that is at risk of being evicted
                long droppedCount = dynamicTable.getInsertCount() - dynamicTable.getMaxEntries();
                if (dynamicFullIndex < droppedCount + EVICTION_THRESHOLD && encoderOutputStream != null) {
                    try {
                        int relativeIndex = (int) (dynamicTable.getInsertCount() - 1 - dynamicFullIndex);
                        duplicate(relativeIndex);
                        dynamicFullIndex = (int) (dynamicTable.getInsertCount() - 1);
                    } catch (IOException e) {
                        // ignore or handle
                    }
                }

                if (dynamicFullIndex < ricBefore) {
                    // Indexed Header Field (Section 4.5.2)
                    // 1Txxxxxx, T=0 (dynamic)
                    // Relative Index = Base - 1 - Absolute Index
                    // Let's use Base = ricBefore.
                    long relativeIndex = ricBefore - 1 - dynamicFullIndex;
                    writePrefixInt(headerBlock, INDEXED_PREFIX, INDEXED_PREFIX_BITS, relativeIndex);
                } else {
                    // Indexed Header Field With Post-Base Index (Section 4.5.3)
                    // 0001xxxx
                    long postBaseIndex = dynamicFullIndex - ricBefore;
                    writePrefixInt(headerBlock, INDEXED_POST_BASE_PREFIX, INDEXED_POST_BASE_PREFIX_BITS, postBaseIndex);
                }
                maxRicNeeded = Math.max(maxRicNeeded, (long) dynamicFullIndex + 1);
                continue;
            }

            // Not found in tables, decide whether to index
            if (encoderOutputStream != null && shouldIndex(header)) {
                insertIntoDynamicTable(header);
                long absoluteIndex = dynamicTable.getInsertCount() - 1;
                // Indexed Header Field With Post-Base Index (Section 4.5.3)
                // 0001xxxx
                long postBaseIndex = absoluteIndex - ricBefore;
                writePrefixInt(headerBlock, INDEXED_POST_BASE_PREFIX, INDEXED_POST_BASE_PREFIX_BITS, postBaseIndex);
                maxRicNeeded = Math.max(maxRicNeeded, absoluteIndex + 1);
                continue;
            }

            Integer staticNameIndex = NAME_TO_INDEX.get(header.name());
            if (staticNameIndex != null) {
                // Literal Header Field With Name Reference (Section 4.5.4)
                // 01NTxxxx, N=0, T=1 (static)
                writePrefixInt(headerBlock, LITERAL_WITH_NAME_REF_PREFIX | LITERAL_NAME_REF_STATIC_BIT, LITERAL_WITH_NAME_REF_PREFIX_BITS, staticNameIndex);
                encodeString(headerBlock, header.value());
            } else {
                // Literal Header Field Without Name Reference (Section 4.5.6)
                // 001NHxxx, N=0, H - use huffman code
                encodeString(headerBlock, header.name(), LITERAL_WITHOUT_NAME_REF_PREFIX_BITS, LITERAL_WITHOUT_NAME_REF_PREFIX);
                encodeString(headerBlock, header.value());
            }
        }

        headerBlock.flip();

        ByteBuffer buffer = ByteBuffer.allocate(headerBlock.remaining() + HEADER_BLOCK_PREFIX_SIZE);

        // RFC 9204 Section 4.5.1.  Header Block Prefix
        long maxEntries = dynamicTable.getMaxEntries();
        if (maxRicNeeded == 0) {
            writePrefixInt(buffer, 0, RIC_PREFIX_BITS, 0);
        } else {
            long fullRange = 2 * maxEntries;
            if (fullRange == 0) {
                // If maxEntries is 0, we can't have maxRicNeeded > 0.
                // But let's be safe.
                writePrefixInt(buffer, 0, RIC_PREFIX_BITS, 0);
            } else {
                long encodedRic = (maxRicNeeded % fullRange) + 1;
                writePrefixInt(buffer, 0, RIC_PREFIX_BITS, encodedRic);
            }
        }
        
        // Sign bit and Delta Base
        if (ricBefore >= maxRicNeeded) {
            writePrefixInt(buffer, 0, DELTA_BASE_PREFIX_BITS, ricBefore - maxRicNeeded);
        } else {
            writePrefixInt(buffer, DELTA_BASE_SIGN_BIT, DELTA_BASE_PREFIX_BITS, maxRicNeeded - ricBefore - 1);
        }
        
        buffer.put(headerBlock);
        buffer.flip();

        // Track the RIC for this stream
        if (maxRicNeeded > 0) {
            StreamRicEntry entry = streamRicEntries.computeIfAbsent(streamId, StreamRicEntry::new);
            if (maxRicNeeded > entry.maxRicNeeded) {
                entry.maxRicNeeded = maxRicNeeded;
                if (maxRicNeeded > knownReceivedCount && entry.heapIndex == -1) {
                    blockedCount++;
                }
                ricHeap.insertOrUpdate(entry);
            }
        }

        return buffer;
    }

    private void updateBlockedCount() {
        while (!ricHeap.isEmpty() && ricHeap.peek().getTimeoutTimestamp() <= knownReceivedCount) {
            ricHeap.poll();
            blockedCount--;
        }
    }

    protected Integer findInDynamicTable(String name, String value) {
        for (long i = dynamicTable.getInsertCount() - 1; i >= 0; i--) {
            Header entry = dynamicTable.get(i);
            if (entry != null && entry.name().equals(name) && entry.value().equals(value)) {
                return (int) i;
            }
        }
        return null;
    }

    protected boolean shouldIndex(Header header) {
        // Simple heuristic: index if not too large
        if (dynamicTable.getMaxCapacity() == 0) return false;

        // Respect peer's blocked streams limit
        if (maxPeerBlockedStreams > 0 && blockedCount >= maxPeerBlockedStreams) {
            return false;
        }

        return (header.name().length() + header.value().length() + 32) < indexingThreshold;
    }

    @Override
    public void setMaxBlockedStreams(long maxBlockedStreams) {
        this.maxPeerBlockedStreams = maxBlockedStreams;
    }

    public void insertIntoDynamicTable(Header header) throws IOException {
        if (encoderOutputStream == null) return;
        
        dynamicTable.add(header);
        Integer staticNameIndex = NAME_TO_INDEX.get(header.name());
        if (staticNameIndex != null) {
            // Insert With Name Reference (Section 4.3.2)
            // 1Txxxxxx, T=1 (static)
            if (logger.isDebugEnabled()) {
                logger.debug("Encoder sending Insert With Name Reference (static): index={}, value={}", staticNameIndex, header.value());
            }
            writeEncoderInt(ENCODER_INSERT_NAME_REF_PREFIX | ENCODER_INSERT_STATIC_BIT, ENCODER_INSERT_NAME_REF_PREFIX_BITS, staticNameIndex);
            encodeEncoderString(header.value());
        } else {
            // Insert With Literal Name (Section 4.3.3)
            // 01xxxxxx
            if (logger.isDebugEnabled()) {
                logger.debug("Encoder sending Insert With Literal Name: name={}, value={}", header.name(), header.value());
            }
            encodeEncoderString(header.name(), ENCODER_INSERT_LITERAL_NAME_PREFIX_BITS, ENCODER_INSERT_LITERAL_NAME_PREFIX);
            encodeEncoderString(header.value());
        }
        encoderOutputStream.flush();
    }

    protected void writeEncoderInt(int firstByte, int prefixBits, long value) throws IOException {
        ByteBuffer temp = ByteBuffer.allocate(INT_MAX_ENCODED_SIZE);
        writePrefixInt(temp, firstByte, prefixBits, value);
        temp.flip();
        encoderOutputStream.write(temp.array(), 0, temp.limit());
    }

    protected void encodeEncoderString(String value) throws IOException {
        encodeEncoderString(value, STRING_LENGTH_PREFIX_BITS, 0);
    }

    protected void encodeEncoderString(String value, int prefixBits, int firstByte) throws IOException {
        ByteBuffer temp = ByteBuffer.allocate(value.length() * 2 + INT_MAX_ENCODED_SIZE);
        encodeString(temp, value, prefixBits, firstByte);
        temp.flip();
        encoderOutputStream.write(temp.array(), 0, temp.limit());
    }

    protected void encodeString(ByteBuffer buffer, String value) {
        encodeString(buffer, value, STRING_LENGTH_PREFIX_BITS, 0);
    }

    protected void encodeString(ByteBuffer buffer, String value, int prefixBits, int firstByte) {
        byte[] bytes = value.getBytes();
        byte[] huffmanBytes = Huffman.encode(bytes);

        if (huffmanBytes.length < bytes.length) {
            writePrefixInt(buffer, firstByte | (1 << prefixBits), prefixBits, huffmanBytes.length);
            buffer.put(huffmanBytes);
        } else {
            writePrefixInt(buffer, firstByte, prefixBits, bytes.length);
            buffer.put(bytes);
        }
    }

    protected void writePrefixInt(ByteBuffer buffer, int firstByte, int prefixBits, long value) {
        int mask = (1 << prefixBits) - 1;
        if (value < mask) {
            buffer.put((byte) (firstByte | (int)value));
        } else {
            buffer.put((byte) (firstByte | mask));
            value -= mask;
            while (value >= VARINT_MAX_SINGLE_BYTE) {
                buffer.put((byte) ((value & VARINT_7BIT_MASK) | VARINT_CONTINUATION_BIT));
                value >>>= VARINT_SHIFT;
            }
            buffer.put((byte) value);
        }
    }

    @Override
    public void onDecoderData(ByteBuffer frame) {
        while (frame.hasRemaining()) {
            int firstByte = frame.get() & 0xFF;
            try {
                if ((firstByte & 0x80) != 0) {
                    // Section Acknowledgment (Section 4.4.2)
                    // 1xxxxxxx
                    long streamId = decodePrefixInt(frame, firstByte, 7);
                    if (logger.isDebugEnabled()) {
                        logger.debug("Encoder received Section Acknowledgment: streamId={}", streamId);
                    }
                    sectionAcknowledgment(streamId);
                } else if ((firstByte & 0x40) != 0) {
                    // Stream Cancellation (Section 4.4.1)
                    // 01xxxxxx
                    long streamId = decodePrefixInt(frame, firstByte, 6);
                    if (logger.isDebugEnabled()) {
                        logger.debug("Encoder received Stream Cancellation: streamId={}", streamId);
                    }
                    streamCancelled(streamId);
                } else {
                    // Insert Count Increment (Section 4.4.3)
                    // 00xxxxxx
                    long increment = decodePrefixInt(frame, firstByte, 6);
                    if (logger.isDebugEnabled()) {
                        logger.debug("Encoder received Insert Count Increment: increment={}", increment);
                    }
                    insertCountIncrement(increment);
                }
            } catch (QpackException e) {
                // Should we stop processing or just throw? 
                // The interface doesn't allow throwing checked exceptions from onDecoderData.
                // QpackException is a RuntimeException though.
                throw e;
            } catch (Exception e) {
                throw new QpackException(QpackException.QPACK_DECODER_STREAM_ERROR, "Failed to decode decoder instruction: " + e.getMessage());
            }
        }
    }

    private long decodePrefixInt(ByteBuffer buffer, int firstByte, int prefixBits) {
        int mask = (1 << prefixBits) - 1;
        long value = firstByte & mask;
        if (value < mask) {
            return value;
        }

        int shift = 0;
        while (true) {
            int b = buffer.get() & 0xFF;
            value += (long) (b & VARINT_7BIT_MASK) << shift;
            if ((b & VARINT_CONTINUATION_BIT) == 0) {
                break;
            }
            shift += VARINT_SHIFT;
        }
        return value;
    }

    protected void sectionAcknowledgment(long streamId) throws QpackException {
        StreamRicEntry entry = streamRicEntries.remove(streamId);
        if (entry == null) {
            // According to RFC 9204 Section 4.4.2, Section Acknowledgment is sent for header blocks.
            // If we don't track it, it might be already unblocked or never blocked.
            // However, an acknowledgment for a stream that never used dynamic table is not an error but redundant.
            return;
        }
        knownReceivedCount = Math.max(knownReceivedCount, entry.maxRicNeeded);
        if (entry.heapIndex != -1) {
            ricHeap.remove(entry);
            blockedCount--;
        }
        updateBlockedCount();
    }

    protected void streamCancelled(long streamId) {
        StreamRicEntry entry = streamRicEntries.remove(streamId);
        if (entry != null) {
            if (entry.heapIndex != -1) {
                ricHeap.remove(entry);
                blockedCount--;
            }
        }
    }

    protected void insertCountIncrement(long increment) throws QpackException {
        knownReceivedCount += increment;
        updateBlockedCount();
        if (knownReceivedCount > dynamicTable.getInsertCount()) {
            // It is not strictly an error in RFC if it's within (2 * MaxEntries) limit maybe?
            // But we don't have MaxEntries properly yet.
            // Actually Section 4.4.3: "An Increment value that... causes the Known Received Count to exceed the total number of dynamic table insertions... MUST be treated as a decoder stream error of type H3_QPACK_DECODER_STREAM_ERROR."
            throw new QpackException(QpackException.QPACK_DECODER_STREAM_ERROR, "Received Insert Count Increment exceeding actual inserts");
        }
    }

    public void duplicate(int index) throws IOException {
        if (encoderOutputStream == null) return;
        // Duplicate (Section 4.3.4)
        // 000xxxxx
        if (logger.isDebugEnabled()) {
            logger.debug("Encoder sending Duplicate instruction: index={}", index);
        }
        writeEncoderInt(ENCODER_DUPLICATE_PREFIX, ENCODER_DUPLICATE_PREFIX_BITS, index);
        long absoluteIndex = dynamicTable.getInsertCount() - index - 1;
        Header entry = dynamicTable.get(absoluteIndex);
        if (entry == null) throw new IOException("Invalid dynamic table index: " + absoluteIndex);
        dynamicTable.add(entry);
        encoderOutputStream.flush();
    }

    @Override
    public void close() throws IOException {
        if (encoderOutputStream != null) {
            encoderOutputStream.close();
        }
    }

    @Override
    public void setDynamicTableCapacity(long capacity) {
        dynamicTable.setCapacity(capacity);
        if (encoderOutputStream != null) {
            try {
                if (logger.isDebugEnabled()) {
                    logger.debug("Encoder sending Set Dynamic Table Capacity instruction: capacity={}", capacity);
                }
                writeEncoderInt(ENCODER_CAPACITY_PREFIX, ENCODER_CAPACITY_PREFIX_BITS, capacity);
                encoderOutputStream.flush();
            } catch (IOException e) {
                // Ignore
            }
        }
    }

    long getKnownReceivedCount() {
        return knownReceivedCount;
    }
}
