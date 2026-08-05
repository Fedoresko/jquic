/*
 * Copyright 2026 Fedor Malyshev
 *
 * Licensed under the Apache License, Version 2.0 (the "License") ;
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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

class TimerWheelSchedulerTest {

    private TimerWheelScheduler scheduler;
    private final long startNs = 1_000_000_000L; // 1 second in Ns

    @BeforeEach
    void setUp() {
        scheduler = new TimerWheelScheduler(startNs);
    }

    @Test
    @DisplayName("Test basic scheduling and polling")
    void testBasicScheduling() {
        TimerWheelScheduler.ScheduledEvent event = new TimerWheelScheduler.ScheduledEvent(
                TimerWheelScheduler.EventType.LOSS_DETECTION, 123L);
        
        // Schedule at startNs + 200us (2 slots ahead)
        scheduler.scheduleAt(startNs + 200_000L, event);
        
        // Poll at startNs + 100us - should be empty
        assertTrue(scheduler.getNewRecords(startNs + 100_000L).isEmpty());
        
        // Poll at startNs + 200us - should have the event
        ArrayList<TimerWheelScheduler.ScheduledEvent> records = scheduler.getNewRecords(startNs + 200_000L);
        assertEquals(1, records.size());
        assertEquals(event, records.get(0));
    }

    @Test
    @DisplayName("Test multiple events in the same slot")
    void testMultipleEventsInSameSlot() {
        TimerWheelScheduler.ScheduledEvent event1 = new TimerWheelScheduler.ScheduledEvent(
                TimerWheelScheduler.EventType.LOSS_DETECTION, 1L);
        TimerWheelScheduler.ScheduledEvent event2 = new TimerWheelScheduler.ScheduledEvent(
                TimerWheelScheduler.EventType.LOSS_DETECTION, 2L);
        
        scheduler.scheduleAt(startNs + 500_000L, event1);
        scheduler.scheduleAt(startNs + 500_000L, event2);
        
        ArrayList<TimerWheelScheduler.ScheduledEvent> records = scheduler.getNewRecords(startNs + 500_000L);
        assertEquals(2, records.size());
        assertTrue(records.contains(event1));
        assertTrue(records.contains(event2));
    }

    @Test
    @DisplayName("Test events in different slots polled incrementally")
    void testEventsInDifferentSlots() {
        TimerWheelScheduler.ScheduledEvent event1 = new TimerWheelScheduler.ScheduledEvent(
                TimerWheelScheduler.EventType.LOSS_DETECTION, 1L);
        TimerWheelScheduler.ScheduledEvent event2 = new TimerWheelScheduler.ScheduledEvent(
                TimerWheelScheduler.EventType.LOSS_DETECTION, 2L);
        
        scheduler.scheduleAt(startNs + 100_000L, event1);
        scheduler.scheduleAt(startNs + 300_000L, event2);
        
        // Poll slot 1
        ArrayList<TimerWheelScheduler.ScheduledEvent> records1 = scheduler.getNewRecords(startNs + 100_000L);
        assertEquals(1, records1.size());
        assertEquals(event1, records1.getFirst());
        
        // Poll slot 2 (empty)
        assertTrue(scheduler.getNewRecords(startNs + 200_000L).isEmpty());
        
        // Poll slot 3
        ArrayList<TimerWheelScheduler.ScheduledEvent> records2 = scheduler.getNewRecords(startNs + 300_000L);
        assertEquals(1, records2.size());
        assertEquals(event2, records2.getFirst());
    }

    @Test
    @DisplayName("Test large time jump causing wheel wrap-around")
    void testLargeTimeJump() {
        TimerWheelScheduler.ScheduledEvent event = new TimerWheelScheduler.ScheduledEvent(
                TimerWheelScheduler.EventType.LOSS_DETECTION, 1L);
        
        // Schedule an event at startNs + 100us
        scheduler.scheduleAt(startNs + 100_000L, event);
        
        // Jump time by more than wheel length (2000 slots * 100us = 200ms)
        // new time = startNs + 300ms
        ArrayList<TimerWheelScheduler.ScheduledEvent> records = scheduler.getNewRecords(startNs + 300_000_000L);
        
        // The event at 100us should have been drained during the catch-up
        assertEquals(1, records.size());
        assertEquals(event, records.getFirst());
    }

    @Test
    @DisplayName("Test scheduling too far in the future throws exception")
    void testScheduleTooFarInFuture() {
        TimerWheelScheduler.ScheduledEvent event = new TimerWheelScheduler.ScheduledEvent(
                TimerWheelScheduler.EventType.LOSS_DETECTION, 1L);
        
        // Wheel length is 2000. Each slot is 100,000 ns.
        // lastDrainedSlot = 1,000,000,000 / 100,000 = 10,000.
        // It should fall in last slot by default
        // Time for slot 12,000 = 12,000 * 100,000 = 1,200,000,000.
        long tooFar = 1_200_000_000L;
        
        scheduler.scheduleAt(tooFar, event);
        assertTrue(scheduler.getNewRecords(1_199_899_990).isEmpty());
        assertEquals(1, scheduler.getNewRecords(1_199_900_000).size());
    }

    @Test
    @DisplayName("Test polling at same time or in the past")
    void testPollingAtSameTimeOrPast() {
        TimerWheelScheduler.ScheduledEvent event = new TimerWheelScheduler.ScheduledEvent(
                TimerWheelScheduler.EventType.LOSS_DETECTION, 1L);
        
        scheduler.scheduleAt(startNs + 100_000L, event);
        
        // First poll
        assertEquals(1, scheduler.getNewRecords(startNs + 100_000L).size());
        
        // Second poll at same time
        assertTrue(scheduler.getNewRecords(startNs + 100_000L).isEmpty());
        
        // Poll in the past - should not crash, should return empty
        assertTrue(scheduler.getNewRecords(startNs).isEmpty());
    }

    @Test
    @DisplayName("Test schedule at exact limit")
    void testScheduleAtExactLimit() {
        TimerWheelScheduler.ScheduledEvent event = new TimerWheelScheduler.ScheduledEvent(
                TimerWheelScheduler.EventType.LOSS_DETECTION, 1L);
        
        // lastDrainedSlot = 10,000. Max slot = 11,999.
        // Time for slot 11,999 = 1,199,900,000 ns.
        long limit = 1_199_900_000L;
        
        // Should not throw
        scheduler.scheduleAt(limit, event);
        
        // To poll it, we need to advance time
        ArrayList<TimerWheelScheduler.ScheduledEvent> records = scheduler.getNewRecords(limit);
        assertEquals(1, records.size());
        assertEquals(event, records.getFirst());
    }
    @Test
    @DisplayName("Test schedule in the past")
    void testScheduleInPast() {
        TimerWheelScheduler.ScheduledEvent event = new TimerWheelScheduler.ScheduledEvent(
                TimerWheelScheduler.EventType.LOSS_DETECTION, 1L);
        
        // Advance lastDrainedSlot to 10,005
        scheduler.getNewRecords(startNs + 500_000L);
        
        // Schedule at startNs (slot 10,000) or current lastDrainedSlot (slot 10,005)
        // Both should throw IllegalArgumentException
        assertThrows(IllegalArgumentException.class, () -> scheduler.scheduleAt(startNs, event));

        assertThrows(IllegalArgumentException.class, () -> scheduler.scheduleAt(startNs + 500_000L, event));
    }
}
