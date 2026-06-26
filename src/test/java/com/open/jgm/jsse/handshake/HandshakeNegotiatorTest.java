package com.open.jgm.jsse.handshake;

import com.open.jgm.jsse.CipherSuite;
import com.open.jgm.jsse.CompressionMethod;
import com.open.jgm.jsse.ProtocolVersion;
import com.open.jgm.jsse.record.Alert;
import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class HandshakeNegotiatorTest {

    @Test
    public void negotiateClientHelloSelectsSupportedValues() throws Exception {
        List<CompressionMethod> compressions = new ArrayList<CompressionMethod>();
        compressions.add(CompressionMethod.NULL);

        HandshakeNegotiator.Negotiated negotiated = HandshakeNegotiator.negotiateClientHello(
                Collections.singletonList(ProtocolVersion.NTLS_1_1),
                Collections.singletonList(CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3),
                ProtocolVersion.NTLS_1_1,
                Collections.singletonList(CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3),
                compressions);

        Assert.assertEquals(ProtocolVersion.NTLS_1_1, negotiated.getProtocolVersion());
        Assert.assertEquals(CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3, negotiated.getCipherSuite());
        Assert.assertEquals(CompressionMethod.NULL, negotiated.getCompressionMethod());
    }

    @Test
    public void negotiateClientHelloRejectsUnsupportedProtocol() {
        try {
            HandshakeNegotiator.negotiateClientHello(
                    Collections.singletonList(ProtocolVersion.NTLS_1_1),
                    Collections.singletonList(CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3),
                    ProtocolVersion.getInstance(3, 3),
                    Collections.singletonList(CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3),
                    Collections.singletonList(CompressionMethod.NULL));
            Assert.fail();
        } catch (HandshakeNegotiator.NegotiationException expected) {
            Assert.assertEquals(Alert.Description.PROTOCOL_VERSION, expected.getDescription());
        }
    }

    @Test
    public void negotiateClientHelloRejectsNoSharedCipherSuite() {
        try {
            HandshakeNegotiator.negotiateClientHello(
                    Collections.singletonList(ProtocolVersion.NTLS_1_1),
                    Collections.singletonList(CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3),
                    ProtocolVersion.NTLS_1_1,
                    Collections.<CipherSuite>emptyList(),
                    Collections.singletonList(CompressionMethod.NULL));
            Assert.fail();
        } catch (HandshakeNegotiator.NegotiationException expected) {
            Assert.assertEquals(Alert.Description.HANDSHAKE_FAILURE, expected.getDescription());
        }
    }

    @Test
    public void negotiateClientHelloRejectsMissingNullCompression() {
        try {
            HandshakeNegotiator.negotiateClientHello(
                    Collections.singletonList(ProtocolVersion.NTLS_1_1),
                    Collections.singletonList(CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3),
                    ProtocolVersion.NTLS_1_1,
                    Collections.singletonList(CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3),
                    Collections.singletonList(CompressionMethod.ZLIB));
            Assert.fail();
        } catch (HandshakeNegotiator.NegotiationException expected) {
            Assert.assertEquals(Alert.Description.ILEGAL_PARAMETER, expected.getDescription());
        }
    }

    @Test
    public void validateServerHelloRejectsUnsupportedCipherSuite() {
        try {
            HandshakeNegotiator.validateServerHello(
                    Collections.singletonList(ProtocolVersion.NTLS_1_1),
                    Collections.<CipherSuite>emptyList(),
                    ProtocolVersion.NTLS_1_1,
                    CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3,
                    CompressionMethod.NULL);
            Assert.fail();
        } catch (HandshakeNegotiator.NegotiationException expected) {
            Assert.assertEquals(Alert.Description.HANDSHAKE_FAILURE, expected.getDescription());
        }
    }

    @Test
    public void validateServerHelloRejectsNonNullCompression() {
        try {
            HandshakeNegotiator.validateServerHello(
                    Collections.singletonList(ProtocolVersion.NTLS_1_1),
                    Collections.singletonList(CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3),
                    ProtocolVersion.NTLS_1_1,
                    CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3,
                    CompressionMethod.ZLIB);
            Assert.fail();
        } catch (HandshakeNegotiator.NegotiationException expected) {
            Assert.assertEquals(Alert.Description.ILEGAL_PARAMETER, expected.getDescription());
        }
    }
}
