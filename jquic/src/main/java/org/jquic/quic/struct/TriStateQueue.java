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

import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

public class TriStateQueue<T> {
    private final AtomicReference<T> ref = new AtomicReference<>();
    private final T emptySate;
    private final T processedState;

    public TriStateQueue(T emptyState, T processedState) {
        this.emptySate = emptyState;
        this.processedState = processedState;
        ref.set(processedState);
    }

    public boolean put(T val, long sleepNs, long timeoutNs) throws TimeoutException {
        long start = System.nanoTime();
        int count = 0;
        while (true) {
            if (ref.compareAndSet(processedState, val)) {
                return true;
            }
            if (ref.compareAndSet(emptySate, val)) {
                return false;
            }
            count++;
            if (count < 10) {
                Thread.onSpinWait();
            } else  {
                if (System.nanoTime() - start > timeoutNs) {
                    throw new TimeoutException();
                }
                LockSupport.parkNanos(sleepNs);
            }
        }
    }

    public T poll() {
        T res = ref.get();
        if (res == emptySate) {
            T res2 = ref.compareAndExchange(emptySate, processedState);
            if (res2 == emptySate) {
                return null;
            } else {
                ref.set(emptySate);
                return res2;
            }
        }
        if (res == processedState) {
            return null;
        }
        ref.set(emptySate);
        return res;
    }

}
