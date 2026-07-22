package org.jquic.quic.streamapi.impl;

import org.jquic.quic.buffers.PoolBuffer;

public record OutboxRecord(long connectionId, long timeToSendNs, PoolBuffer data) {
}
