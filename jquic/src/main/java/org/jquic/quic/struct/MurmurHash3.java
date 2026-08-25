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
package org.jquic.quic.struct;

public final class MurmurHash3 {

    private static final long C1 = 0x87c37b91114253d5L;
    private static final long C2 = 0x4cf5ad432745937fL;

    public static long[] hash(final byte[] data) {
        long h1 = 0L;
        long h2 = 0L;

        final int nblocks = data.length >> 4; // Divided by 16

        // --- Body ---
        for (int i = 0; i < nblocks; i++) {
            final int index = (i << 4);
            long k1 = getLongLittleEndian(data, index);
            long k2 = getLongLittleEndian(data, index + 8);

            // Mix k1
            k1 *= C1;
            k1 = Long.rotateLeft(k1, 31);
            k1 *= C2;
            h1 ^= k1;

            h1 = Long.rotateLeft(h1, 27);
            h1 += h2;
            h1 = h1 * 5 + 0x52dce729;

            // Mix k2
            k2 *= C2;
            k2 = Long.rotateLeft(k2, 33);
            k2 *= C1;
            h2 ^= k2;

            h2 = Long.rotateLeft(h2, 31);
            h2 += h1;
            h2 = h2 * 5 + 0x38495ab5;
        }

        // --- Tail ---
        final int tailStart = (nblocks << 4);
        long k1 = 0;
        long k2 = 0;

        switch (data.length & 15) {
            case 15: k2 ^= ((long) data[tailStart + 14] & 0xFF) << 48;
            case 14: k2 ^= ((long) data[tailStart + 13] & 0xFF) << 40;
            case 13: k2 ^= ((long) data[tailStart + 12] & 0xFF) << 32;
            case 12: k2 ^= ((long) data[tailStart + 11] & 0xFF) << 24;
            case 11: k2 ^= ((long) data[tailStart + 10] & 0xFF) << 16;
            case 10: k2 ^= ((long) data[tailStart + 9] & 0xFF) << 8;
            case  9: k2 ^= ((long) data[tailStart + 8] & 0xFF);
                k2 *= C2; k2 = Long.rotateLeft(k2, 33); k2 *= C1; h2 ^= k2;

            case  8: k1 ^= ((long) data[tailStart + 7] & 0xFF) << 56;
            case  7: k1 ^= ((long) data[tailStart + 6] & 0xFF) << 48;
            case  6: k1 ^= ((long) data[tailStart + 5] & 0xFF) << 40;
            case  5: k1 ^= ((long) data[tailStart + 4] & 0xFF) << 32;
            case  4: k1 ^= ((long) data[tailStart + 3] & 0xFF) << 24;
            case  3: k1 ^= ((long) data[tailStart + 2] & 0xFF) << 16;
            case  2: k1 ^= ((long) data[tailStart + 1] & 0xFF) << 8;
            case  1: k1 ^= ((long) data[tailStart]) & 0xFF;
                k1 *= C1; k1 = Long.rotateLeft(k1, 31); k1 *= C2; h1 ^= k1;
        }

        // --- Finalization ---
        h1 ^= data.length;
        h2 ^= data.length;

        h1 += h2;
        h2 += h1;

        h1 = fmix64(h1);
        h2 = fmix64(h2);

        h1 += h2;
        h2 += h1;

        return new long[] { h1, h2 };
    }

    private static long getLongLittleEndian(final byte[] src, final int index) {
        return ((long) src[index] & 0xFF)
                | ((long) src[index + 1] & 0xFF) << 8
                | ((long) src[index + 2] & 0xFF) << 16
                | ((long) src[index + 3] & 0xFF) << 24
                | ((long) src[index + 4] & 0xFF) << 32
                | ((long) src[index + 5] & 0xFF) << 40
                | ((long) src[index + 6] & 0xFF) << 48
                | ((long) src[index + 7] & 0xFF) << 56;
    }

    private static long fmix64(long k) {
        k ^= k >>> 33;
        k *= 0xff51afd7ed558ccdL;
        k ^= k >>> 33;
        k *= 0xc4ceb9fe1a85ec53L;
        k ^= k >>> 33;
        return k;
    }
}