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

/**
 * Common interface for QPACK instructions.
 */
public interface QpackInstruction {
    
    /**
     * Encoder instructions (sent by encoder, received by decoder).
     */
    interface EncoderInstruction extends QpackInstruction {
        /**
         * Set Dynamic Table Capacity (Section 4.3.1)
         */
        record SetCapacity(long capacity) implements EncoderInstruction {
            @Override
            public String toString() {
                return "SetCapacity{capacity=" + capacity + "}";
            }
        }

        /**
         * Insert With Name Reference (Section 4.3.2)
         */
        record InsertWithNameRef(boolean isStatic, int nameIndex, String value) implements EncoderInstruction {
            @Override
            public String toString() {
                return "InsertWithNameRef{isStatic=" + isStatic + ", nameIndex=" + nameIndex + ", value='" + value + "'}";
            }
        }

        /**
         * Insert With Literal Name (Section 4.3.3)
         */
        record InsertWithLiteralName(String name, String value) implements EncoderInstruction {
            @Override
            public String toString() {
                return "InsertWithLiteralName{name='" + name + "', value='" + value + "'}";
            }
        }

        /**
         * Duplicate (Section 4.3.4)
         */
        record Duplicate(int index) implements EncoderInstruction {
            @Override
            public String toString() {
                return "Duplicate{index=" + index + "}";
            }
        }
    }

    /**
     * Decoder instructions (sent by decoder, received by encoder).
     */
    interface DecoderInstruction extends QpackInstruction {
        /**
         * Section Acknowledgment (Section 4.4.2)
         */
        record SectionAck(long streamId) implements DecoderInstruction {
            @Override
            public String toString() {
                return "SectionAck{streamId=" + streamId + "}";
            }
        }

        /**
         * Stream Cancellation (Section 4.4.1)
         */
        record StreamCancel(long streamId) implements DecoderInstruction {
            @Override
            public String toString() {
                return "StreamCancel{streamId=" + streamId + "}";
            }
        }

        /**
         * Insert Count Increment (Section 4.4.3)
         */
        record InsertCountIncrement(long increment) implements DecoderInstruction {
            @Override
            public String toString() {
                return "InsertCountIncrement{increment=" + increment + "}";
            }
        }
    }
}
