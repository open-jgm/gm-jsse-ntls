package com.open.jgm.jsse.handshake;

import com.open.jgm.jsse.CipherSuite;
import com.open.jgm.jsse.CompressionMethod;
import com.open.jgm.jsse.ProtocolVersion;
import com.open.jgm.jsse.record.Alert;

import java.util.Arrays;
import java.util.List;

public final class HandshakeNegotiator {

    private HandshakeNegotiator() {
    }

    public static Negotiated negotiateClientHello(List<ProtocolVersion> enabledProtocols,
            List<CipherSuite> enabledCipherSuites, ProtocolVersion peerProtocol,
            List<CipherSuite> peerCipherSuites, List<CompressionMethod> peerCompressions)
            throws NegotiationException {
        if (!containsProtocol(enabledProtocols, peerProtocol)) {
            throw new NegotiationException(Alert.Description.PROTOCOL_VERSION,
                    "unsupported protocol version: " + peerProtocol);
        }
        if (!containsNullCompression(peerCompressions)) {
            throw new NegotiationException(Alert.Description.ILEGAL_PARAMETER,
                    "client did not offer NULL compression");
        }
        CipherSuite selected = selectCipherSuite(enabledCipherSuites, peerCipherSuites);
        if (selected == null) {
            throw new NegotiationException(Alert.Description.HANDSHAKE_FAILURE,
                    "no shared cipher suite");
        }
        return new Negotiated(peerProtocol, selected, CompressionMethod.NULL);
    }

    public static Negotiated validateServerHello(List<ProtocolVersion> enabledProtocols,
            List<CipherSuite> enabledCipherSuites, ProtocolVersion selectedProtocol,
            CipherSuite selectedCipherSuite, CompressionMethod selectedCompression)
            throws NegotiationException {
        if (!containsProtocol(enabledProtocols, selectedProtocol)) {
            throw new NegotiationException(Alert.Description.PROTOCOL_VERSION,
                    "server selected unsupported protocol: " + selectedProtocol);
        }
        if (!containsCipherSuite(enabledCipherSuites, selectedCipherSuite)) {
            throw new NegotiationException(Alert.Description.HANDSHAKE_FAILURE,
                    "server selected unsupported cipher suite: " + selectedCipherSuite);
        }
        if (!isNullCompression(selectedCompression)) {
            throw new NegotiationException(Alert.Description.ILEGAL_PARAMETER,
                    "server selected unsupported compression: " + selectedCompression);
        }
        return new Negotiated(selectedProtocol, selectedCipherSuite, CompressionMethod.NULL);
    }

    private static CipherSuite selectCipherSuite(List<CipherSuite> enabledCipherSuites,
            List<CipherSuite> peerCipherSuites) {
        if (enabledCipherSuites == null || peerCipherSuites == null) {
            return null;
        }
        for (CipherSuite enabled : enabledCipherSuites) {
            if (containsCipherSuite(peerCipherSuites, enabled)) {
                return enabled;
            }
        }
        return null;
    }

    private static boolean containsProtocol(List<ProtocolVersion> protocols, ProtocolVersion protocol) {
        return protocols != null && protocol != null && protocols.contains(protocol);
    }

    private static boolean containsCipherSuite(List<CipherSuite> cipherSuites, CipherSuite cipherSuite) {
        if (cipherSuites == null || cipherSuite == null) {
            return false;
        }
        for (CipherSuite candidate : cipherSuites) {
            if (sameCipherSuite(candidate, cipherSuite)) {
                return true;
            }
        }
        return false;
    }

    private static boolean sameCipherSuite(CipherSuite left, CipherSuite right) {
        return left == right || (left != null && right != null && Arrays.equals(left.getId(), right.getId()));
    }

    private static boolean containsNullCompression(List<CompressionMethod> compressionMethods) {
        if (compressionMethods == null) {
            return false;
        }
        for (CompressionMethod method : compressionMethods) {
            if (isNullCompression(method)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isNullCompression(CompressionMethod compressionMethod) {
        return compressionMethod != null && compressionMethod.getValue() == CompressionMethod.NULL.getValue();
    }

    public static final class Negotiated {
        private final ProtocolVersion protocolVersion;
        private final CipherSuite cipherSuite;
        private final CompressionMethod compressionMethod;

        private Negotiated(ProtocolVersion protocolVersion, CipherSuite cipherSuite,
                CompressionMethod compressionMethod) {
            this.protocolVersion = protocolVersion;
            this.cipherSuite = cipherSuite;
            this.compressionMethod = compressionMethod;
        }

        public ProtocolVersion getProtocolVersion() {
            return protocolVersion;
        }

        public CipherSuite getCipherSuite() {
            return cipherSuite;
        }

        public CompressionMethod getCompressionMethod() {
            return compressionMethod;
        }
    }

    public static final class NegotiationException extends Exception {
        private final Alert.Description description;

        private NegotiationException(Alert.Description description, String message) {
            super(message);
            this.description = description;
        }

        public Alert.Description getDescription() {
            return description;
        }
    }
}
