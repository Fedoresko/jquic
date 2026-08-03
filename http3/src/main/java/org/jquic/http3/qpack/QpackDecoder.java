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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

public class QpackDecoder implements Decoder {
    private static final Logger logger = LoggerFactory.getLogger(QpackDecoder.class);

    public static final int DEFAULT_MAX_PERMITTED_CAPACITY = 4096;

    private static final int INDEXED_PREFIX = 0x80;
    private static final int INDEXED_STATIC_BIT = 0x40;
    private static final int LITERAL_WITH_NAME_REF_PREFIX = 0x40;
    private static final int LITERAL_WITHOUT_NAME_REF_PREFIX = 0x20;

    private static final int ENCODER_INSERT_NAME_REF_PREFIX = 0x80;
    private static final int ENCODER_INSERT_NAME_REF_PREFIX_BITS = 6;
    private static final int ENCODER_INSERT_STATIC_BIT = 0x40;
    private static final int ENCODER_INSERT_LITERAL_NAME_PREFIX = 0x40;
    private static final int ENCODER_INSERT_LITERAL_NAME_PREFIX_BITS = 5;
    private static final int ENCODER_CAPACITY_PREFIX = 0x20;
    private static final int ENCODER_CAPACITY_PREFIX_BITS = 5;
    private static final int ENCODER_DUPLICATE_PREFIX = 0x00;
    private static final int ENCODER_DUPLICATE_PREFIX_BITS = 5;

    private static final int DECODER_CANCEL_PREFIX = 0x40;
    private static final int DECODER_CANCEL_PREFIX_BITS = 6;
    private static final int DECODER_INCREMENT_PREFIX = 0x00;
    private static final int DECODER_INCREMENT_PREFIX_BITS = 6;

    private static final int RIC_PREFIX_BITS = 8;
    private static final int INDEXED_PREFIX_BITS = 6;
    private static final int INDEXED_POST_BASE_PREFIX_BITS = 4;
    private static final int LITERAL_WITH_NAME_REF_PREFIX_BITS = 4;
    private static final int LITERAL_WITHOUT_NAME_REF_PREFIX_BITS = 3;
    private static final int LITERAL_POST_BASE_NAME_REF_PREFIX_BITS = 3;

    private static final int STRING_LENGTH_PREFIX_BITS = 7;
    private static final int DELTA_BASE_PREFIX_BITS = 7;
    private static final int DELTA_BASE_SIGN_BIT = 0x80;

    private static final int VARINT_7BIT_MASK = 0x7F;
    private static final int VARINT_CONTINUATION_BIT = 0x80;
    private static final int VARINT_SHIFT = 7;
    private static final int VARINT_MAX_SINGLE_BYTE = 128;

    protected final QpackDynamicTable dynamicTable = new QpackDynamicTable();
    private final DataOutputStream decoderOutputStream;
    private final Set<Long> activeStreams = new LinkedHashSet<>();
    private long maxPermittedCapacity;
    private Consumer<Long> unblockedStreamListener;

    public QpackDecoder() {
        this(null);
    }

    public QpackDecoder(DataOutputStream decoderOutputStream) {
        this(decoderOutputStream, DEFAULT_MAX_PERMITTED_CAPACITY);
    }

    public QpackDecoder(DataOutputStream decoderOutputStream, long maxPermittedCapacity) {
        this.decoderOutputStream = decoderOutputStream;
        this.maxPermittedCapacity = maxPermittedCapacity;
        this.dynamicTable.setCapacity(maxPermittedCapacity);
    }

    /**
     * Add a listener to be triggered when insertCount is updated 
     * @param listener - consumer of new insertCount
     */
    public void setUnblockedStreamListener(Consumer<Long> listener) {
        this.unblockedStreamListener = listener;
    }

    @Override
    public List<Header> decodeHeaders(long streamId, ByteBuffer frame) throws IOException {
        activeStreams.add(streamId);
        
        // Save initial position for possible blocking
        int initialPosition = frame.position();

        // RFC 9204 Section 4.5.1.  Required Insert Count
        long encodedRic = decodePrefixInt(frame);
        long maxEntries = dynamicTable.getMaxEntries();
        long requiredInsertCount;
        if (encodedRic == 0) {
            requiredInsertCount = 0;
        } else {
            if (maxEntries == 0) {
                // If maxEntries is 0, encodedRic must be 0. But we got non-zero.
                // However, for testing RIC reconstruction with tiny capacity, we might need a way to bypass this if we want to test wrap-around.
                // Section 4.5.1: "The encoder... MUST NOT encode a header block that relies on a Required Insert Count greater than the current insert count."
                // "A Required Insert Count of 0 indicates that no dynamic table entries are used."
                // If maxEntries is 0, no dynamic table entries can be used.
                throw new IOException("Encoded RIC is non-zero but MaxEntries is 0");
            }
            long fullRange = 2 * maxEntries;
            long totalAccumulatedIndex = dynamicTable.getInsertCount();
            
            // RFC 9204:
            // MaxEntries = floor(MaxTableCapacity / 32)
            // FullRange = 2 * MaxEntries
            // MaxRIC = TotalAccumulatedIndex + MaxEntries
            // if EncodedRIC == 0:
            //   RequiredInsertCount = 0
            // else:
            //   RequiredInsertCount = Reconstruct(EncodedRIC)
            
            long maxRic = totalAccumulatedIndex + maxEntries;
            requiredInsertCount = maxRic - (maxRic % fullRange) + (encodedRic - 1);
            if (requiredInsertCount > maxRic) {
                requiredInsertCount -= fullRange;
            }
        }
        
        // RFC 9204 Section 4.5.1.  Base
        int firstByte = frame.get() & 0xFF;
        boolean sign = (firstByte & DELTA_BASE_SIGN_BIT) != 0;
        long deltaBase = decodePrefixInt(frame, firstByte, DELTA_BASE_PREFIX_BITS);
        long base = sign ? (requiredInsertCount - deltaBase - 1) : (requiredInsertCount + deltaBase);

        if (requiredInsertCount > dynamicTable.getInsertCount()) {
            // Rewind to initial position
            frame.position(initialPosition);
            throw new QpackRequiredInsertCountException(requiredInsertCount, frame);
        }

        List<Header> headers = new ArrayList<>();
        while (frame.hasRemaining()) {
            int b = frame.get() & 0xFF;
            if ((b & INDEXED_PREFIX) != 0) {
                // Indexed Header Field (Section 4.5.2)
                // 1Txxxxxx
                boolean isStatic = (b & INDEXED_STATIC_BIT) != 0;
                int index = (int) decodePrefixInt(frame, b, INDEXED_PREFIX_BITS);
                if (isStatic) {
                    QpackStaticTable.Entry entry = QpackStaticTable.get(index);
                    if (entry == null) throw new IOException("Invalid static table index: " + index);
                    headers.add(new Header(entry.name(), entry.value()));
                } else {
                    long absoluteIndex = base - index - 1;
                    Header entry = dynamicTable.get(absoluteIndex);
                    if (entry == null) throw new IOException("Invalid dynamic table index: " + absoluteIndex);
                    headers.add(entry);
                }
            } else if ((b & LITERAL_WITH_NAME_REF_PREFIX) != 0) {
                // Literal Header Field With Name Reference (Section 4.5.4)
                // 01NTHxxx
                boolean isStatic = (b & 0x10) != 0;
                int nameIndex = (int) decodePrefixInt(frame, b, LITERAL_WITH_NAME_REF_PREFIX_BITS);
                String name;
                if (isStatic) {
                    QpackStaticTable.Entry entry = QpackStaticTable.get(nameIndex);
                    if (entry == null) throw new IOException("Invalid static table index: " + nameIndex);
                    name = entry.name();
                } else {
                    long absoluteIndex = base - nameIndex - 1;
                    Header entry = dynamicTable.get(absoluteIndex);
                    if (entry == null) throw new IOException("Invalid dynamic table index: " + absoluteIndex);
                    name = entry.name();
                }
                String value = decodeString(frame);
                headers.add(new Header(name, value));
            } else if ((b & LITERAL_WITHOUT_NAME_REF_PREFIX) != 0) {
                // Literal Header Field Without Name Reference (Section 4.5.6)
                // 001NHxxx
                // H bit - means use Huffman code
                // N bit - means intermediary is permitted to add this field line to the dynamic table
                String name = decodeString(frame, b, LITERAL_WITHOUT_NAME_REF_PREFIX_BITS);
                String value = decodeString(frame);
                headers.add(new Header(name, value));
            } else if ((b & 0x10) != 0) {
                // Indexed Header Field With Post-Base Index (Section 4.5.3)
                // 0001xxxx
                int index = (int) decodePrefixInt(frame, b, INDEXED_POST_BASE_PREFIX_BITS);
                long absoluteIndex = base + index;
                Header entry = dynamicTable.get(absoluteIndex);
                if (entry == null) throw new IOException("Invalid dynamic table index: " + absoluteIndex);
                headers.add(entry);
            } else {
                // Literal Header Field With Post-Base Name Reference (Section 4.5.5)
                // 0000xxxx
                int nameIndex = (int) decodePrefixInt(frame, b, LITERAL_POST_BASE_NAME_REF_PREFIX_BITS);
                long absoluteIndex = base + nameIndex;
                Header entry = dynamicTable.get(absoluteIndex);
                if (entry == null) throw new IOException("Invalid dynamic table index: " + absoluteIndex);
                String value = decodeString(frame);
                headers.add(new Header(entry.name(), value));
            }
        }

        return headers;
    }

    @Override
    public void onEncoderData(ByteBuffer frame) {
        long startInsertCount = dynamicTable.getInsertCount();
        while (frame.hasRemaining()) {
            int b = frame.get() & 0xFF;
            try {
                if ((b & ENCODER_INSERT_NAME_REF_PREFIX) != 0) {
                    // Insert With Name Reference (Section 4.3.2)
                    boolean isStatic = (b & ENCODER_INSERT_STATIC_BIT) != 0;
                    int nameIndex = (int) decodePrefixInt(frame, b, ENCODER_INSERT_NAME_REF_PREFIX_BITS);
                    String value = decodeString(frame);
                    if (logger.isDebugEnabled()) {
                        logger.debug("Decoder received Insert With Name Reference: static={}, index={}, value={}", isStatic, nameIndex, value);
                    }
                    insertWithNameReference(isStatic, nameIndex, value);
                } else if ((b & ENCODER_INSERT_LITERAL_NAME_PREFIX) != 0) {
                    // Insert With Literal Name (Section 4.3.3)
                    String name = decodeString(frame, b, ENCODER_INSERT_LITERAL_NAME_PREFIX_BITS);
                    String value = decodeString(frame);
                    if (logger.isDebugEnabled()) {
                        logger.debug("Decoder received Insert With Literal Name: name={}, value={}", name, value);
                    }
                    insertWithLiteralName(name, value);
                } else if ((b & ENCODER_CAPACITY_PREFIX) == ENCODER_CAPACITY_PREFIX) {
                    // Set Dynamic Table Capacity (Section 4.3.1)
                    long capacity = decodePrefixInt(frame, b, ENCODER_CAPACITY_PREFIX_BITS);
                    if (logger.isDebugEnabled()) {
                        logger.debug("Decoder received Set Dynamic Table Capacity: capacity={}", capacity);
                    }
                    setDynamicTableCapacity(capacity);
                } else if ((b & 0xE0) == ENCODER_DUPLICATE_PREFIX) {
                    // Duplicate (Section 4.3.4)
                    int index = (int) decodePrefixInt(frame, b, ENCODER_DUPLICATE_PREFIX_BITS);
                    if (logger.isDebugEnabled()) {
                        logger.debug("Decoder received Duplicate: index={}", index);
                    }
                    duplicate(index);
                } else {
                    throw new IOException("Unknown encoder instruction: " + Integer.toHexString(b));
                }
            } catch (Exception e) {
                if (e instanceof RuntimeException) throw (RuntimeException) e;
                throw new RuntimeException("Error decoding encoder instruction: b=" + Integer.toHexString(b), e);
            }
        }
        long increment = dynamicTable.getInsertCount() - startInsertCount;
        if (increment > 0) {
            if (logger.isDebugEnabled()) {
                logger.debug("QPACK Decoder processed {} entries from encoder stream", increment);
            }
            sendInsertCountIncrement(increment);
            if (unblockedStreamListener != null) {
                unblockedStreamListener.accept(dynamicTable.getInsertCount());
            }
        }
    }

    private void sendInsertCountIncrement(long increment) {
        if (decoderOutputStream == null || increment <= 0) return;
        try {
            // RFC 9204 Section 4.4.3.  Insert Count Increment
            // 00nnnnnn
            if (logger.isDebugEnabled()) {
                logger.debug("Decoder sending Insert Count Increment instruction: increment={}", increment);
            }
            int mask = (1 << DECODER_INCREMENT_PREFIX_BITS) - 1;
            if (increment < mask) {
                decoderOutputStream.write((int) (DECODER_INCREMENT_PREFIX | increment));
            } else {
                decoderOutputStream.write(DECODER_INCREMENT_PREFIX | mask);
                long remaining = increment - mask;
                while (remaining >= VARINT_MAX_SINGLE_BYTE) {
                    decoderOutputStream.write((int) (remaining & VARINT_7BIT_MASK) | VARINT_CONTINUATION_BIT);
                    remaining >>>= VARINT_SHIFT;
                }
                decoderOutputStream.write((int) remaining);
            }
            decoderOutputStream.flush();
        } catch (IOException e) {
            // Ignore stream errors for now
        }
    }

    @Override
    public void close() throws IOException {
        if (decoderOutputStream == null) return;
        for (Long streamId : activeStreams) {
            sendStreamCancellation(streamId);
        }
        decoderOutputStream.flush();
        activeStreams.clear();
    }

    @Override
    public void cancelStream(long streamId) {
        if (activeStreams.remove(streamId)) {
            try {
                sendStreamCancellation(streamId);
                decoderOutputStream.flush();
            } catch (IOException e) {
                // Ignore
            }
        }
    }

    private void sendStreamCancellation(long streamId) throws IOException {
        if (decoderOutputStream == null) return;
        // RFC 9204 Section 4.4.1.  Stream Cancellation
        // 01xxxxxx
        if (logger.isDebugEnabled()) {
            logger.debug("Decoder sending Stream Cancellation instruction: streamId={}", streamId);
        }
        int mask = (1 << DECODER_CANCEL_PREFIX_BITS) - 1;
        if (streamId < mask) {
            decoderOutputStream.write(DECODER_CANCEL_PREFIX | (int) streamId);
        } else {
            decoderOutputStream.write(DECODER_CANCEL_PREFIX | mask);
            long remaining = streamId - mask;
            while (remaining >= VARINT_MAX_SINGLE_BYTE) {
                decoderOutputStream.write((int) (remaining & VARINT_7BIT_MASK) | VARINT_CONTINUATION_BIT);
                remaining >>>= VARINT_SHIFT;
            }
            decoderOutputStream.write((int) remaining);
        }
    }

    private long decodePrefixInt(ByteBuffer buffer) throws IOException {
        if (!buffer.hasRemaining()) throw new IOException("Unexpected end of buffer");
        return decodePrefixInt(buffer, buffer.get() & 0xFF, QpackDecoder.RIC_PREFIX_BITS);
    }

    private long decodePrefixInt(ByteBuffer buffer, int firstByte, int prefixBits) throws IOException {
        int mask = (1 << prefixBits) - 1;
        long value = firstByte & mask;
        if (value < mask) {
            return value;
        }

        int shift = 0;
        while (true) {
            if (!buffer.hasRemaining()) throw new IOException("Unexpected end of buffer");
            int b = buffer.get() & 0xFF;
            value += (long) (b & VARINT_7BIT_MASK) << shift;
            if ((b & VARINT_CONTINUATION_BIT) == 0) {
                break;
            }
            shift += VARINT_SHIFT;
        }
        return value;
    }

    private String decodeString(ByteBuffer buffer) throws IOException {
        if (!buffer.hasRemaining()) throw new IOException("Unexpected end of buffer");
        int b = buffer.get() & 0xFF;
        return decodeString(buffer, b, STRING_LENGTH_PREFIX_BITS);
    }

    private String decodeString(ByteBuffer buffer, int firstByte, int prefixBits) throws IOException {
        boolean huffman = (firstByte & (1 << prefixBits)) != 0;
        int length = (int) decodePrefixInt(buffer, firstByte, prefixBits);
        if (huffman) {
            try {
                // Huffman.decode expects a ByteBuffer that it will read from current position to its limit.
                // We create a temporary duplicate to avoid modifying the original buffer's limit.
                ByteBuffer temp = buffer.duplicate();
                temp.limit(temp.position() + length);
                byte[] decoded = Huffman.decode(temp);
                buffer.position(buffer.position() + length); // Move position after decoded data
                return new String(decoded);
            } catch (Exception e) {
                throw new IOException("Huffman decoding failed: " + e.getMessage(), e);
            }
        } else {
            byte[] data = new byte[length];
            buffer.get(data);
            return new String(data);
        }
    }

    public void setDynamicTableCapacity(long capacity) throws QpackException {
        if (logger.isDebugEnabled()) {
            logger.debug("Decoder setting dynamic table capacity to {}", capacity);
        }
        if (capacity > maxPermittedCapacity) {
            throw new QpackException(QpackException.QPACK_ENCODER_STREAM_ERROR,
                    "Encoder attempted to set capacity " + capacity + " which exceeds max permitted " + maxPermittedCapacity);
        }
        dynamicTable.setCapacity(capacity);
    }

    private void insertWithNameReference(boolean isStatic, int nameIndex, String value) throws IOException {
        String name;
        if (isStatic) {
            QpackStaticTable.Entry entry = QpackStaticTable.get(nameIndex);
            if (entry == null) throw new IOException("Invalid static table index: " + nameIndex);
            name = entry.name();
        } else {
            long absoluteIndex = dynamicTable.getInsertCount() - nameIndex - 1;
            Header entry = dynamicTable.get(absoluteIndex);
            if (entry == null) throw new IOException("Invalid dynamic table index: " + absoluteIndex);
            name = entry.name();
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Decoder inserting into dynamic table (name reference): {}={}", name, value);
        }
        dynamicTable.add(new Header(name, value));
    }

    private void insertWithLiteralName(String name, String value) {
        if (logger.isDebugEnabled()) {
            logger.debug("Decoder inserting into dynamic table (literal name): {}={}", name, value);
        }
        dynamicTable.add(new Header(name, value));
    }

    private void duplicate(int index) throws IOException {
        long absoluteIndex = dynamicTable.getInsertCount() - index - 1;
        Header entry = dynamicTable.get(absoluteIndex);
        if (entry == null) throw new IOException("Invalid dynamic table index: " + absoluteIndex);
        if (logger.isDebugEnabled()) {
            logger.debug("Decoder duplicating entry at relative index {} (absoluteIndex={}): {}={}", index, absoluteIndex, entry.name(), entry.value());
        }
        dynamicTable.add(entry);
    }
}
