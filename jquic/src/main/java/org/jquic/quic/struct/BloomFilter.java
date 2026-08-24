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

public class BloomFilter {
    private static final int NUM_BITS = 1048576; // 2^20 bits, enough for ~100k items with low false positive
    private static final int MASK = NUM_BITS - 1;
    private final long[] bits = new long[NUM_BITS / 64];

    public void markAdd(long value) {
        setBit((int) (mix1(value) & MASK));
        setBit((int) (mix2(value) & MASK));
        setBit((int) (mix3(value) & MASK));
        setBit((int) (mix4(value) & MASK));
        setBit((int) (mix5(value) & MASK));
        setBit((int) (mix6(value) & MASK));
        setBit((int) (mix7(value) & MASK));
    }

    public boolean contains(long value) {
        return getBit((int) (mix1(value) & MASK)) &&
               getBit((int) (mix2(value) & MASK)) &&
               getBit((int) (mix3(value) & MASK)) &&
               getBit((int) (mix4(value) & MASK)) &&
               getBit((int) (mix5(value) & MASK)) &&
               getBit((int) (mix6(value) & MASK)) &&
               getBit((int) (mix7(value) & MASK));
    }

    public void clear() {
        java.util.Arrays.fill(bits, 0L);
    }

    private void setBit(int index) {
        bits[index >>> 6] |= (1L << (index & 63));
    }

    private boolean getBit(int index) {
        return (bits[index >>> 6] & (1L << (index & 63))) != 0;
    }


    // Mixer Variation 1 (Excellent avalanche characteristics)
    public static long mix1(long x) {
        x ^= x >>> 30;
        x *= 0xbf58476d1ce4e5b9L;
        x ^= x >>> 27;
        x *= 0x94d049bb133111ebL;
        x ^= x >>> 31;
        return x;
    }

    // Mixer Variation 2 
    public static long mix2(long x) {
        x ^= x >>> 33;
        x *= 0xff51afd7ed558ccdL;
        x ^= x >>> 33;
        x *= 0xc4ceb9fe1a85ec53L;
        x ^= x >>> 33;
        return x;
    }

    // Mixer Variation 3
    public static long mix3(long x) {
        x = (x ^ (x >>> 30)) * 0x4bfb925b7e52432dL;
        x = (x ^ (x >>> 27)) * 0x5a1d78194a42f01dL;
        return x ^ (x >>> 31);
    }

    // Mixer Variation 4
    public static long mix4(long x) {
        x ^= x >>> 33;
        x *= 0x62a9d9ed799705f5L;
        x ^= x >>> 28;
        x *= 0xcb24d0a5c88c35b3L;
        x ^= x >>> 32;
        return x;
    }

    // Mixer Variation 5
    public static long mix5(long x) {
        x = (x ^ (x >>> 31)) * 0x7fb5d329728ea185L;
        x = (x ^ (x >>> 27)) * 0x81adde05ba933be5L;
        return x ^ (x >>> 33);
    }

    // Mixer Variation 6
    public static long mix6(long x) {
        x ^= x >>> 29;
        x *= 0x5552222222222222L;
        x ^= x >>> 33;
        x *= 0x3333333333333333L;
        x ^= x >>> 29;
        return x;
    }

    // Mixer Variation 7
    public static long mix7(long x) {
        x = (x ^ (x >>> 30)) * 0xbf58476d1ce4e5b9L;
        x = (x ^ (x >>> 27)) * 0x94d049bb133111ebL;
        x = (x ^ (x >>> 31)) * 0x7fb5d329728ea185L;
        return x ^ (x >>> 33);
    }
}
