package com.open.jgm.jsse;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import java.util.Collections;
import java.util.Enumeration;

public class SessionContext implements SSLSessionContext {

    private int sessionCacheSize;
    private int sessionTimeout;

    public SessionContext() {
    }

    public Enumeration<byte[]> getIds() {
        return Collections.emptyEnumeration();
    }

    public SSLSession getSession(byte[] sessionId) {
        return null;
    }

    public int getSessionCacheSize() {
        return sessionCacheSize;
    }

    public void setSessionCacheSize(int size) throws IllegalArgumentException {
        if (size < 0) {
            throw new IllegalArgumentException("session cache size must not be negative");
        }
        sessionCacheSize = size;
    }

    public int getSessionTimeout() {
        return sessionTimeout;
    }

    public void setSessionTimeout(int seconds) throws IllegalArgumentException {
        if (seconds < 0) {
            throw new IllegalArgumentException("session timeout must not be negative");
        }
        sessionTimeout = seconds;
    }
}
