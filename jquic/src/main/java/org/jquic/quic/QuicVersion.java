package org.jquic.quic;

public enum QuicVersion {
    QUIC_VERSION_1(0x00000001),
    QUIC_VERSION_2(0x6b3343cf),

    UNKNOWN(0);

    public final int val;

    QuicVersion(int val) {
        this.val = val;
    }

    public static QuicVersion of(int anInt) {
        if (anInt == QUIC_VERSION_1.val) {
            return QUIC_VERSION_1;
        } else if (anInt == QUIC_VERSION_2.val) {
            return QUIC_VERSION_2;
        } else {
            return UNKNOWN;
        }
    }
}
