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

import java.util.ArrayList;
import java.util.List;

public class SortedIntervalsTest {

    public SortedIntervalsTest() {
        System.out.println("[DEBUG_LOG] NativeSortedIntervalsTest instance created");
    }

    @Test
    public void testBasicAddition() {
        System.out.println("[DEBUG_LOG] Running testBasicAddition");
        SortedIntervals intervals = new SortedIntervals(10);
        intervals.add(10);
        intervals.add(20);
        intervals.add(5);

        List<SortedIntervals.Interval> result = new ArrayList<>();
        intervals.forEach(result::add);

        assertEquals(3, result.size());
        assertEquals(new SortedIntervals.Interval(20, 20), result.get(0));
        assertEquals(new SortedIntervals.Interval(10, 10), result.get(1));
        assertEquals(new SortedIntervals.Interval(5, 5), result.get(2));
    }

    @Test
    public void testDuplicateAddition() {
        SortedIntervals intervals = new SortedIntervals(10);
        intervals.add(10);
        intervals.add(10);

        List<SortedIntervals.Interval> result = new ArrayList<>();
        intervals.forEach(result::add);

        assertEquals(1, result.size());
        assertEquals(new SortedIntervals.Interval(10, 10), result.get(0));
    }

    @Test
    public void testLeftMerge() {
        SortedIntervals intervals = new SortedIntervals(10);
        intervals.add(10);
        intervals.add(11);

        List<SortedIntervals.Interval> result = new ArrayList<>();
        intervals.forEach(result::add);

        assertEquals(1, result.size());
        assertEquals(new SortedIntervals.Interval(10, 11), result.get(0));
    }

    @Test
    public void testRightMerge() {
        SortedIntervals intervals = new SortedIntervals(10);
        intervals.add(10);
        intervals.add(9);

        List<SortedIntervals.Interval> result = new ArrayList<>();
        intervals.forEach(result::add);

        assertEquals(1, result.size());
        assertEquals(new SortedIntervals.Interval(9, 10), result.get(0));
    }

    @Test
    public void testBridgeMerge() {
        SortedIntervals intervals = new SortedIntervals(10);
        intervals.add(8);
        intervals.add(10);
        intervals.add(9);

        List<SortedIntervals.Interval> result = new ArrayList<>();
        intervals.forEach(result::add);

        assertEquals(1, result.size());
        assertEquals(new SortedIntervals.Interval(8, 10), result.get(0));
    }

    @Test
    public void testComplexMerge() {
        SortedIntervals intervals = new SortedIntervals(10);
        intervals.add(1);
        intervals.add(3);
        intervals.add(5);
        intervals.add(2);
        intervals.add(4);

        List<SortedIntervals.Interval> result = new ArrayList<>();
        intervals.forEach(result::add);

        assertEquals(1, result.size());
        assertEquals(new SortedIntervals.Interval(1, 5), result.get(0));
    }

    @Test
    public void testCapacityExceeded() {
        SortedIntervals intervals = new SortedIntervals(2);
        intervals.add(1);
        intervals.add(3);
        assertThrows(IllegalStateException.class, () -> intervals.add(5));
    }

    @Test
    public void testInvalidCapacity() {
        assertThrows(IllegalArgumentException.class, () -> new SortedIntervals(256));
    }

    @Test
    public void testEmptyIteration() {
        SortedIntervals intervals = new SortedIntervals(10);
        assertFalse(intervals.iterator().hasNext());
    }

    @Test
    public void testMergeWithExistingIntervals() {
        SortedIntervals intervals = new SortedIntervals(10);
            // [1, 2]
        intervals.add(1);
        intervals.add(2);

        // [4, 5]
        intervals.add(4);
        intervals.add(5);

        // Add 3 to bridge them -> [1, 5]
        intervals.add(3);

        List<SortedIntervals.Interval> result = new ArrayList<>();
        intervals.forEach(result::add);

        assertEquals(1, result.size());
        assertEquals(new SortedIntervals.Interval(1, 5), result.get(0));
    }

    @Test
    public void testReusingReclaimedNodes() {
        // This is a bit tricky to test without reflection, but we can try to trigger it
        // by creating intervals, merging them (which should reclaim nodes), and then creating more.
        SortedIntervals intervals = new SortedIntervals(2);
        intervals.add(1); // Node 0: [1, 1]
        intervals.add(3); // Node 1: [3, 3]

        // Now we have 2 nodes, capacity is 2.
        // Merge them by adding 2.
        intervals.add(2); // Should merge Node 0 and Node 1. Node 1 should be reclaimed.

        // Now we should have 1 node active [1, 3] and 1 reclaimed.
        // We should be able to add another disjoint point.
        intervals.add(5); // Should use reclaimed Node 1.

        List<SortedIntervals.Interval> result = new ArrayList<>();
        intervals.forEach(result::add);

        assertEquals(2, result.size());
        assertEquals(new SortedIntervals.Interval(5, 5), result.get(0));
        assertEquals(new SortedIntervals.Interval(1, 3), result.get(1));
    }

    @Test
    public void testCascadeMerge() {
        SortedIntervals intervals = new SortedIntervals(10);
            // [1, 1], [3, 3], [5, 5], [7, 7]
        intervals.add(1);
        intervals.add(3);
        intervals.add(5);
        intervals.add(7);

        // Bridge [1,1] and [3,3] -> [1, 3]
        intervals.add(2);
        // Bridge [5,5] and [7,7] -> [5, 7]
        intervals.add(6);

        List<SortedIntervals.Interval> intermediate = new ArrayList<>();
        intervals.forEach(intermediate::add);
        assertEquals(2, intermediate.size());
        assertEquals(new SortedIntervals.Interval(5, 7), intermediate.get(0));
        assertEquals(new SortedIntervals.Interval(1, 3), intermediate.get(1));

        // Bridge everything -> [1, 7]
        intervals.add(4);

        List<SortedIntervals.Interval> result = new ArrayList<>();
        intervals.forEach(result::add);
        assertEquals(1, result.size());
        assertEquals(new SortedIntervals.Interval(1, 7), result.get(0));
    }

    @Test
    public void testNearCapacityAndReclaim() {
        int cap = 100;
        SortedIntervals intervals = new SortedIntervals(cap);
            // Fill to capacity with disjoint points: 0, 2, 4, ... 198
        for (int i = 0; i < cap; i++) {
            intervals.add(i * 2);
        }

        // Verify capacity reached
        assertThrows(IllegalStateException.class, () -> intervals.add(1000));

        // Merge everything by filling gaps: 1, 3, 5, ...
        // This should reclaim nodes
        for (int i = 0; i < cap - 1; i++) {
            intervals.add(i * 2 + 1);
        }

        // Now we should have one big interval [0, 198]
        List<SortedIntervals.Interval> result = new ArrayList<>();
        intervals.forEach(result::add);
        assertEquals(1, result.size());
        assertEquals(new SortedIntervals.Interval(0, 198), result.get(0));

        // Since we reclaimed many nodes, we should be able to add more disjoint points
        for (int i = 0; i < cap - 1; i++) {
            intervals.add(1000 + i * 2);
        }

        List<SortedIntervals.Interval> finalResult = new ArrayList<>();
        intervals.forEach(finalResult::add);
        assertEquals(cap, finalResult.size());
        assertEquals(new SortedIntervals.Interval(1000 + (cap - 2) * 2, 1000 + (cap - 2) * 2), finalResult.get(0));
        assertEquals(new SortedIntervals.Interval(0, 198), finalResult.get(cap - 1));
    }

    @Test
    public void testDifferentOrdering() {
        // Ascending
        SortedIntervals intervals = new SortedIntervals(10);
        for (int i = 0; i < 5; i++) intervals.add(i);
        assertEquals(1, countIntervals(intervals));
        assertEquals(new SortedIntervals.Interval(0, 4), intervals.iterator().next());

        // Descending
        intervals = new SortedIntervals(10);
        for (int i = 4; i >= 0; i--) intervals.add(i);
        assertEquals(1, countIntervals(intervals));
        assertEquals(new SortedIntervals.Interval(0, 4), intervals.iterator().next());

        // Inside-out
        intervals = new SortedIntervals(10);
        intervals.add(2);
        intervals.add(1);
        intervals.add(3);
        intervals.add(0);
        intervals.add(4);
        assertEquals(1, countIntervals(intervals));
        assertEquals(new SortedIntervals.Interval(0, 4), intervals.iterator().next());
    }

    @Test
    public void testMaximumAllowedCapacity() {
        SortedIntervals intervals = new SortedIntervals(255);
        for (int i = 0; i < 255; i++) {
            intervals.add(i * 2);
        }
        assertEquals(255, countIntervals(intervals));
    }

    private int countIntervals(Iterable<?> iterable) {
        int count = 0;
        for (Object o : iterable) count++;
        return count;
    }

    @Test
    public void testMultipleDisjointIntervals() {
        SortedIntervals intervals = new SortedIntervals(10);
        intervals.add(1);
        intervals.add(5);
        intervals.add(10);

        List<SortedIntervals.Interval> result = new ArrayList<>();
        intervals.forEach(result::add);

        assertEquals(3, result.size());
        assertEquals(new SortedIntervals.Interval(10, 10), result.get(0));
        assertEquals(new SortedIntervals.Interval(5, 5), result.get(1));
        assertEquals(new SortedIntervals.Interval(1, 1), result.get(2));
    }
}

