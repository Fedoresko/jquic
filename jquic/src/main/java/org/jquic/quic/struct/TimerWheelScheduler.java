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

import java.util.ArrayList;
import java.util.LinkedList;

/**
 * Schedules events using a bucket wheel. Each bucket is 100 microseconds.
 */
public class TimerWheelScheduler {
    public enum EventType {
        LOSS_DETECTION,
    }

    public record ScheduledEvent(EventType eventType, long connectionId) {}

    @SuppressWarnings("unchecked")
    private final LinkedList<ScheduledEvent>[] timerWheel = new LinkedList[2000];
    private long lastDrainedSlot;

    public TimerWheelScheduler(long nowNs) {
        for (int i = 0; i < timerWheel.length; i++) {
            timerWheel[i] = new LinkedList<>();
        }
        lastDrainedSlot = nowNs / 100_000;
    }

    /**
     * Poll all new events since the last call.
     * @param nowNs - current time
     * @return list of all new events
     */
    public ArrayList<ScheduledEvent> getNewRecords(long nowNs) {
        long curSlot = (nowNs / 100_000);

        if (curSlot - lastDrainedSlot > timerWheel.length - 1) {
            lastDrainedSlot = curSlot - timerWheel.length + 1;
        }

        ArrayList<ScheduledEvent> recordsToProcess = new ArrayList<>();

        TimerWheelScheduler.ScheduledEvent event;
        for (long slot = lastDrainedSlot; slot <= curSlot; slot ++) {
            while ((event = timerWheel[(int)(slot % timerWheel.length)].poll()) != null) {
                recordsToProcess.add(event);
            }
        }
        lastDrainedSlot = curSlot;
        return recordsToProcess;
    }

    /**
     * Schedule event processing for the particular moment in the future
     * @param timeNs - time of event
     * @param event - event class
     */
    public void scheduleAt(long timeNs, ScheduledEvent event) {
        long slot = (timeNs / 100_000);
        if (slot <= lastDrainedSlot) {
            throw new IllegalArgumentException("Scheduling in the past");
        }
        if (slot - lastDrainedSlot > timerWheel.length - 1) {
            throw new IllegalArgumentException("Not enough slots");
        }
        timerWheel[(int) (slot % timerWheel.length)].add(event);
    }
}
