package org.jquic.quic.packets;

/**
 * Packet type enumeration for identifying different QUIC .
 * Used for retransmission to re-wrap payloads with correct headers.
 */
public enum PacketPhase {
    INITIAL,      // Initial packet (long header)
    HANDSHAKE,    // Handshake packet (long header)
    APPLICATION   // 1-RTT packet (short header)
}
