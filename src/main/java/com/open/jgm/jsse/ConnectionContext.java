package com.open.jgm.jsse;

import java.io.IOException;

public abstract class ConnectionContext {

    public SSLConfiguration sslConfig;
    public boolean isNegotiated = false;
    protected GMSSLContextSpi sslContext;
    protected GMSSLSocket socket;
    protected GMSSLSession session = new GMSSLSession();

    public ConnectionContext(GMSSLContextSpi context, GMSSLSocket socket, SSLConfiguration sslConfig) {
        this.sslContext = context;
        this.sslConfig = sslConfig;
        this.socket = socket;
        this.session = new GMSSLSession(sslConfig.enabledCipherSuites, sslConfig.enabledProtocols);
        this.session.setSessionContext((SessionContext) (sslConfig.isClientMode
                ? context.engineGetClientSessionContext()
                : context.engineGetServerSessionContext()));
    }

    public abstract void kickstart() throws IOException;
}
