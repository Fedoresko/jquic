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

import java.lang.reflect.Array;

public class TimeoutHeap<T extends TimeoutHeap.Entry> {
    private final Class<T> tClass;
    public TimeoutHeap(Class<T> tClass) {
        this.tClass = tClass;
        heap = (T[]) Array.newInstance(tClass ,1024);
    }
    /**
     * Represents an entry that can be managed in a timeout heap.
     * It should keep its heap index internally.
     */
    public interface Entry {
        /**
         * Returns the index of this entry in a timeout heap.
         * @return The index of this entry in a timeout heap, or -1 if is not in heap yet.
         */
        int getTimeoutHeapIndex();

        /**
         * Sets the index of this entry in a timeout heap.
         * @param idx The new index to set for this entry in a timeout heap.
         */
        void setTimeoutHeapIndex(int idx);

        /**
         * Returns the timeout timestamp of this entry. This could be changed any time:
         * {@link  TimeoutHeap#insertOrUpdate(Entry)} should be called to keep heap consistent.
         * @return The timeout timestamp in milliseconds since the epoch.
         */
        long getTimeoutTimestamp();
    }

    private T[] heap;
    private int size = 0;

    /**
     * Retrieves and removes the head of this heap, which is the element with the smallest timeout timestamp.
     *
     * If this heap is empty, returns null.
     *
     * @return the head of this heap, or null if this heap is empty
     */
    public T poll() {
        if (size == 0) return null;
        T entry = heap[0];
        swap(0, --size);
        heap[size] = null;
        siftDown(0);
        return entry;
    }

    public T peek() {
        if (size == 0) return null;
        return heap[0];
    }

    public boolean isEmpty() {
        return size == 0;
    }

    public int size() {
        return size;
    }

    public void remove(T entry) {
        int index = entry.getTimeoutHeapIndex();
        if (index != -1 && index < size) {
            swap(index, --size);
            heap[size] = null;
            if (index < size) {
                siftDown(index);
                siftUp(index);
            }
            entry.setTimeoutHeapIndex(-1);
        }
    }

    /**
     * Inserts a new entry into the heap or updates an existing one based on its timeout timestamp.
     * @param entry The entry to be inserted or updated in the heap.
     */
    public void insertOrUpdate(T entry) {
        if (entry.getTimeoutHeapIndex() == -1) {
            // New entryection: Insert at the bottom and sift up
            if (size == heap.length) growArray();
            heap[size] = entry;
            entry.setTimeoutHeapIndex(size);
            size++;
            siftUp(entry.getTimeoutHeapIndex());
        } else {
            // Existing entryection: Timeout changed, re-sort from its current position
            // Depending on if the deadline increased or decreased:
            siftDown(entry.getTimeoutHeapIndex());
            siftUp(entry.getTimeoutHeapIndex());
        }
    }

    private void growArray() {
        T[] newArray = (T[]) Array.newInstance(tClass, heap.length * 2);
        System.arraycopy(heap, 0, newArray, 0, heap.length);
        heap = newArray;
    }

    private void siftUp(int index) {
        while (index > 0) {
            int parent = (index - 1) >>> 1;
            if (heap[index].getTimeoutTimestamp() >= heap[parent].getTimeoutTimestamp()) break;
            swap(index, parent);
            index = parent;
        }
    }

    private void siftDown(int index) {
        int half = size >>> 1;
        while (index < half) {
            int child = (index << 1) + 1;
            int right = child + 1;
            if (right < size && heap[right].getTimeoutTimestamp() < heap[child].getTimeoutTimestamp()) {
                child = right;
            }
            if (heap[index].getTimeoutTimestamp() <= heap[child].getTimeoutTimestamp()) break;
            swap(index, child);
            index = child;
        }
    }

    private void swap(int i, int j) {
        T temp = heap[i];
        heap[i] = heap[j];
        heap[j] = temp;
        heap[i].setTimeoutHeapIndex(i); // Update the entryection's internal pointer!
        heap[j].setTimeoutHeapIndex(j);
    }


}
