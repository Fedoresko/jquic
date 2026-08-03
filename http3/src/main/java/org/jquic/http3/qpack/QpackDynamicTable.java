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

import java.util.ArrayList;
import java.util.List;

public class QpackDynamicTable {
    public static final int ENTRY_OVERHEAD = 32;
    private final List<Header> entries = new ArrayList<>();
    private long maxCapacity = 0;
    private long currentCapacity = 0;
    private long insertCount = 0;

    public void setCapacity(long capacity) {
        this.maxCapacity = capacity;
        evict();
    }

    public void add(Header header) {
        long entrySize = header.name().length() + header.value().length() + ENTRY_OVERHEAD;
        if (entrySize > maxCapacity) {
            entries.clear();
            currentCapacity = 0;
            return;
        }
        entries.add(header);
        currentCapacity += entrySize;
        insertCount++;
        evict();
    }

    private void evict() {
        while (currentCapacity > maxCapacity && !entries.isEmpty()) {
            Header removed = entries.removeFirst();
            currentCapacity -= (removed.name().length() + removed.value().length() + ENTRY_OVERHEAD);
        }
    }

    public long getMaxCapacity() {
        return maxCapacity;
    }

    public long getMaxEntries() {
        return maxCapacity / ENTRY_OVERHEAD;
    }

    public Header get(long absoluteIndex) {
        long droppedCount = insertCount - entries.size();
        if (absoluteIndex < droppedCount || absoluteIndex >= insertCount) {
            return null;
        }
        return entries.get((int) (absoluteIndex - droppedCount));
    }

    public long getInsertCount() {
        return insertCount;
    }
}
