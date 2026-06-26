package com.open.jgm.jsse;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SSLConfiguration {

    public List<ProtocolVersion> enabledProtocols;
    public List<CipherSuite> enabledCipherSuites;
    public boolean enableSessionCreation;
    public boolean isClientMode;
    public ClientAuthType clientAuthType;

    public SSLConfiguration(GMSSLContextSpi sslContext, boolean isClientMode) {
        setEnabledProtocols(sslContext.getDefaultProtocolVersions(!isClientMode));
        setEnabledCipherSuites(sslContext.getDefaultCipherSuites(!isClientMode));
        this.clientAuthType = ClientAuthType.CLIENT_AUTH_NONE;
        this.isClientMode = isClientMode;
        this.enableSessionCreation = true;
    }

    public List<ProtocolVersion> getEnabledProtocols() {
        return Collections.unmodifiableList(enabledProtocols);
    }

    public void setEnabledProtocols(List<ProtocolVersion> enabledProtocols) {
        this.enabledProtocols = copyProtocols(enabledProtocols);
    }

    public List<CipherSuite> getEnabledCipherSuites() {
        return Collections.unmodifiableList(enabledCipherSuites);
    }

    public void setEnabledCipherSuites(List<CipherSuite> enabledCipherSuites) {
        this.enabledCipherSuites = copyCipherSuites(enabledCipherSuites);
    }

    private static List<ProtocolVersion> copyProtocols(List<ProtocolVersion> protocols) {
        if (protocols == null) {
            throw new IllegalArgumentException("enabled protocols must not be null");
        }
        return new ArrayList<ProtocolVersion>(protocols);
    }

    private static List<CipherSuite> copyCipherSuites(List<CipherSuite> cipherSuites) {
        if (cipherSuites == null) {
            throw new IllegalArgumentException("enabled cipher suites must not be null");
        }
        return new ArrayList<CipherSuite>(cipherSuites);
    }
}
