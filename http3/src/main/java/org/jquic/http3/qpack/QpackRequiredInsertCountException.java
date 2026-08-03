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

import java.io.IOException;
import java.nio.ByteBuffer;

public class QpackRequiredInsertCountException extends IOException {
    private final long requiredInsertCount;
    private final ByteBuffer frame;

    public QpackRequiredInsertCountException(long requiredInsertCount, ByteBuffer frame) {
        super("Required Insert Count " + requiredInsertCount + " not yet reached");
        this.requiredInsertCount = requiredInsertCount;
        this.frame = frame;
    }

    public long getRequiredInsertCount() {
        return requiredInsertCount;
    }

    public ByteBuffer getFrame() {
        return frame;
    }
}
