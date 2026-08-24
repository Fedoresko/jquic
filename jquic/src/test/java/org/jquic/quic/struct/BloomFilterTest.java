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

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class BloomFilterTest {

    @Test
    public void testBasicAddAndContains() {
        BloomFilter bf = new BloomFilter();
        
        long val1 = 123456789L;
        long val2 = 987654321L;
        
        assertFalse(bf.contains(val1));
        assertFalse(bf.contains(val2));
        
        bf.markAdd(val1);
        assertTrue(bf.contains(val1));
        assertFalse(bf.contains(val2));
        
        bf.markAdd(val2);
        assertTrue(bf.contains(val1));
        assertTrue(bf.contains(val2));
    }
    
    @Test
    public void testClear() {
        BloomFilter bf = new BloomFilter();
        long val = 555L;
        
        bf.markAdd(val);
        assertTrue(bf.contains(val));
        
        bf.clear();
        assertFalse(bf.contains(val));
    }
    
    @Test
    public void testFalsePositiveRate() {
        BloomFilter bf = new BloomFilter();
        int n = 100000;
        
        // Add 100k items
        for (int i = 0; i < n; i++) {
            bf.markAdd(i);
        }
        
        // Check 100k items that were added
        for (int i = 0; i < n; i++) {
            assertTrue(bf.contains(i));
        }
        
        // Check false positives in the next 100k items
        int falsePositives = 0;
        for (int i = n; i < 2 * n; i++) {
            if (bf.contains(i)) {
                falsePositives++;
            }
        }
        
        double fpRate = (double) falsePositives / n;
        System.out.println("[DEBUG_LOG] False positives: " + falsePositives + " rate: " + fpRate);
        
        // With m = 2^20 and k = 7, n = 100,000
        // p = (1 - e^(-kn/m))^k
        // kn/m = 700,000 / 1,048,576 ≈ 0.667
        // p = (1 - e^-0.667)^7 ≈ (1 - 0.513)^7 ≈ 0.487^7 ≈ 0.0064
        // 0.6% false positive rate is expected for this configuration.
        // Let's assert it's less than 1% to be safe.
        assertTrue(fpRate < 0.01, "False positive rate too high: " + fpRate);
    }
}
