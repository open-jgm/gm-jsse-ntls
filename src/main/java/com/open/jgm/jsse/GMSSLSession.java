package com.open.jgm.jsse;

import javax.net.ssl.*;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GMSSLSession implements SSLSession {

    public List<CipherSuite> enabledSuites;
    public List<ProtocolVersion> enabledProtocols;
    public X509Certificate[] peerCerts;
    public CipherSuite cipherSuite;
    public ID sessionId;
    public String peerHost;
    public int peerPort;
    public X509KeyManager keyManager;
    public X509TrustManager trustManager;
    public SecureRandom random;
    public boolean peerVerified;
    ProtocolVersion protocol;
    SessionContext sessionContext;
    private long creationTime;
    private long lastAccessedTime;
    private boolean valid;
    private final Map<String, Object> values = Collections.synchronizedMap(new HashMap<String, Object>());

    public GMSSLSession(List<CipherSuite> enabledSuites, List<ProtocolVersion> enabledProtocols) {
        initTimes();
        setEnabledSuites(enabledSuites);
        setEnabledProtocols(enabledProtocols);
        this.peerVerified = false;
    }

    public GMSSLSession() {
        initTimes();
    }

    public void setEnabledSuites(List<CipherSuite> enabledSuites) {
        this.enabledSuites = enabledSuites == null
                ? Collections.<CipherSuite>emptyList()
                : new ArrayList<CipherSuite>(enabledSuites);
    }

    public void setEnabledProtocols(List<ProtocolVersion> enabledProtocols) {
        this.enabledProtocols = enabledProtocols == null
                ? Collections.<ProtocolVersion>emptyList()
                : new ArrayList<ProtocolVersion>(enabledProtocols);
    }

    public void setSessionContext(SessionContext sessionContext) {
        this.sessionContext = sessionContext;
    }

    public void setProtocol(ProtocolVersion protocol) {
        this.protocol = protocol;
    }

    private void initTimes() {
        this.creationTime = System.currentTimeMillis();
        this.lastAccessedTime = creationTime;
        this.valid = true;
    }

    @Override
    public int getApplicationBufferSize() {
        return 16320;
    }

    @Override
    public String getCipherSuite() {
        return cipherSuite.getName();
    }

    @Override
    public long getCreationTime() {
        return creationTime;
    }

    @Override
    public byte[] getId() {
        if (sessionId == null) {
            return new byte[0];
        }
        return sessionId.getId();
    }

    @Override
    public long getLastAccessedTime() {
        return lastAccessedTime;
    }

    @Override
    public Certificate[] getLocalCertificates() {
        if (keyManager == null) {
            return null;
        }
        X509Certificate[] chain = keyManager.getCertificateChain("sign");
        return chain == null ? null : (Certificate[]) chain.clone();
    }

    @Override
    public Principal getLocalPrincipal() {
        Certificate[] certs = getLocalCertificates();
        if (certs == null || certs.length == 0) {
            return null;
        }
        return ((X509Certificate) certs[0]).getSubjectX500Principal();
    }

    @Override
    public int getPacketBufferSize() {
        return 16389;
    }

    @Override
    public String getPeerHost() {
        return peerHost;
    }

    @Override
    public int getPeerPort() {
        return peerPort;
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        X509Certificate[] certs = verifiedPeerCertificates();
        return certs[0].getSubjectX500Principal();
    }

    @Override
    public String getProtocol() {
        return protocol.toString();
    }

    @Override
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        return verifiedPeerCertificates().clone();
    }

    @Override
    public SSLSessionContext getSessionContext() {
        return sessionContext;
    }

    @Override
    public Object getValue(String name) {
        requireValueName(name);
        return values.get(name);
    }

    @Override
    public String[] getValueNames() {
        synchronized (values) {
            return values.keySet().toArray(new String[values.size()]);
        }
    }

    @Override
    public void invalidate() {
        valid = false;
    }

    @Override
    public boolean isValid() {
        return valid;
    }

    @Override
    public void putValue(String name, Object value) {
        requireValueName(name);
        if (value == null) {
            throw new IllegalArgumentException("value must not be null");
        }
        Object oldValue = values.put(name, value);
        if (oldValue instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) oldValue).valueUnbound(new SSLSessionBindingEvent(this, name));
        }
        if (value instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) value).valueBound(new SSLSessionBindingEvent(this, name));
        }
    }

    @Override
    public void removeValue(String name) {
        requireValueName(name);
        Object oldValue = values.remove(name);
        if (oldValue instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) oldValue).valueUnbound(new SSLSessionBindingEvent(this, name));
        }
    }

    @Override
    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        verifiedPeerCertificates();
        return null;
    }

    private X509Certificate[] verifiedPeerCertificates() throws SSLPeerUnverifiedException {
        if (!peerVerified || peerCerts == null || peerCerts.length == 0) {
            throw new SSLPeerUnverifiedException("peer not verified");
        }
        return peerCerts.clone();
    }

    private static void requireValueName(String name) {
        if (name == null) {
            throw new IllegalArgumentException("name must not be null");
        }
    }

    public static class ID {
        private final byte[] id;

        public ID(byte[] id) {
            this.id = id == null ? new byte[0] : id.clone();
        }

        public byte[] getId() {
            return id.clone();
        }
    }
}
