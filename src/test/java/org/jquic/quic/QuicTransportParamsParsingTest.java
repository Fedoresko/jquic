package org.jquic.quic;

import org.conscrypt.Conscrypt;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class QuicTransportParamsParsingTest {
    static {
        Security.addProvider(Conscrypt.newProvider());
    }

    @Test
    void testParseTransportParameters() throws Exception {
        // We want to test that QuicCrypto.parseClientHello (which is private, but maybe we can use reflection 
        // or just test the logic if we were to make it public/accessible)
        // Since I can't modify QuicCrypto.java to make it public, I'll use reflection to call it if possible,
        // or just provide the test as a proof of concept for the suggested changes.

        ByteBuffer hello = buildClientHelloWithParams(
                5000, // initial_max_data (0x04)
                1000, // initial_max_stream_data_bidi_local (0x05)
                2000, // initial_max_stream_data_bidi_remote (0x06)
                3000, // initial_max_stream_data_uni (0x07)
                10,   // initial_max_streams_bidi (0x08)
                5     // initial_max_streams_uni (0x09)
        );

        ConnectionMetadata.ClientMetadataNegotiated parsedHello = QuicCrypto.parseClientHello(hello);

        assertNotNull(parsedHello);

        // Use reflection to check fields
        assertEquals(5000, parsedHello.initialStreamLimits.maxData);
        assertEquals(1000, parsedHello.initialStreamLimits.maxStreamDataBidiLocal);
        assertEquals(2000, parsedHello.initialStreamLimits.maxStreamDataBidiRemote);
        assertEquals(3000, parsedHello.initialStreamLimits.maxStreamDataUni);
        assertEquals(10, parsedHello.initialStreamLimits.maxBidi);
        assertEquals(5, parsedHello.initialStreamLimits.maxUni);
    }

    private Object getFieldValue(Object obj, String fieldName) throws Exception {
        java.lang.reflect.Field field = obj.getClass().getField(fieldName);
        return field.get(obj);
    }

    private ByteBuffer buildClientHelloWithParams(long maxData, long bidiLocal, long bidiRemote, long uni, long streamsBidi, long streamsUni) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
        kpg.initialize(java.security.spec.NamedParameterSpec.X25519);
        KeyPair kp = kpg.generateKeyPair();
        byte[] pubEncoded = kp.getPublic().getEncoded();
        byte[] x25519PubKey = Arrays.copyOfRange(pubEncoded, pubEncoded.length - 32, pubEncoded.length);

        ByteBuffer tp = ByteBuffer.allocate(128);
        // max_idle_timeout (0x01)
        QuicVarint.write(tp, 0x01);
        QuicVarint.write(tp, QuicVarint.sizeOf(30000));
        QuicVarint.write(tp, 30000);

        // initial_max_data (0x04)
        QuicVarint.write(tp, 0x04);
        QuicVarint.write(tp, QuicVarint.sizeOf(maxData));
        QuicVarint.write(tp, maxData);

        // initial_max_stream_data_bidi_local (0x05)
        QuicVarint.write(tp, 0x05);
        QuicVarint.write(tp, QuicVarint.sizeOf(bidiLocal));
        QuicVarint.write(tp, bidiLocal);

        // initial_max_stream_data_bidi_remote (0x06)
        QuicVarint.write(tp, 0x06);
        QuicVarint.write(tp, QuicVarint.sizeOf(bidiRemote));
        QuicVarint.write(tp, bidiRemote);

        // initial_max_stream_data_uni (0x07)
        QuicVarint.write(tp, 0x07);
        QuicVarint.write(tp, QuicVarint.sizeOf(uni));
        QuicVarint.write(tp, uni);

        // initial_max_streams_bidi (0x08)
        QuicVarint.write(tp, 0x08);
        QuicVarint.write(tp, QuicVarint.sizeOf(streamsBidi));
        QuicVarint.write(tp, streamsBidi);

        // initial_max_streams_uni (0x09)
        QuicVarint.write(tp, 0x09);
        QuicVarint.write(tp, QuicVarint.sizeOf(streamsUni));
        QuicVarint.write(tp, streamsUni);

        tp.flip();
        byte[] tpBytes = new byte[tp.remaining()];
        tp.get(tpBytes);

        ByteBuffer extensions = ByteBuffer.allocate(512);
        // supported_versions (0x002b)
        extensions.putShort((short) 0x002b);
        extensions.putShort((short) 3);
        extensions.put((byte) 2);
        extensions.putShort((short) 0x0304);

        // key_share (0x0033)
        extensions.putShort((short) 0x0033);
        extensions.putShort((short) 38);
        extensions.putShort((short) 36);
        extensions.putShort((short) 0x001d);
        extensions.putShort((short) 32);
        extensions.put(x25519PubKey);

        // transport_parameters (0x0039)
        extensions.putShort((short) 0x0039);
        extensions.putShort((short) tpBytes.length);
        extensions.put(tpBytes);

        extensions.flip();
        int extLen = extensions.remaining();

        int bodyLen = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extLen;
        ByteBuffer hello = ByteBuffer.allocate(4 + bodyLen);
        hello.put((byte) 0x01);
        hello.put((byte) ((bodyLen >> 16) & 0xFF));
        hello.put((byte) ((bodyLen >> 8) & 0xFF));
        hello.put((byte) (bodyLen & 0xFF));

        hello.putShort((short) 0x0303);
        hello.put(new byte[32]);
        hello.put((byte) 0);
        hello.putShort((short) 2);
        hello.putShort((short) 0x1301);
        hello.put((byte) 1);
        hello.put((byte) 0x00);
        hello.putShort((short) extLen);
        hello.put(extensions);

        hello.flip();
        return hello;
    }
}
