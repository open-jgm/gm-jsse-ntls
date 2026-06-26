package com.open.jgm.jsse;


import com.open.jgm.jsse.protocol.ClientConnectionContext;
import com.open.jgm.jsse.protocol.ServerConnectionContext;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import java.util.ArrayList;
import java.util.List;

/**
 * GMSSLSocket
 */
public class GMSSLSocket extends SSLSocket {

    private final AppDataInputStream appInput = new AppDataInputStream();
    private final AppDataOutputStream appOutput = new AppDataOutputStream();
    private final ConnectionContext connection;
    private final GMSSLContextSpi context;
    public SSLSessionContext sessionContext;
    public RecordStream recordStream;
    BufferedOutputStream handshakeOut;
    int port;
    private String remoteHost;
    private boolean clientMode = true;
    private Socket underlyingSocket;
    private boolean autoClose;
    private boolean isConnected = false;
    // raw socket in/out
    private InputStream socketIn;
    private OutputStream socketOut;

    public GMSSLSocket(GMSSLContextSpi context, SSLConfiguration sslConfig) {
        this.context = context;
        this.connection = new ServerConnectionContext(context, this, sslConfig);
    }

    GMSSLSocket(GMSSLContextSpi context, String host, int port, boolean clientMode, SSLConfiguration sslConfig,
            InputStream socketIn, OutputStream socketOut) {
        this.context = context;
        this.remoteHost = host;
        this.port = port;
        this.clientMode = clientMode;
        this.socketIn = socketIn;
        this.socketOut = socketOut;
        this.recordStream = new RecordStream(socketIn, socketOut);
        this.isConnected = true;
        if (clientMode) {
            this.connection = new ClientConnectionContext(context, this, sslConfig);
        } else {
            this.connection = new ServerConnectionContext(context, this, sslConfig);
        }
    }

    public GMSSLSocket(GMSSLContextSpi context, String host, int port) throws IOException {
        super(host, port);
        this.context = context;
        this.connection = new ClientConnectionContext(context, this);
        remoteHost = host;
        ensureConnect();
    }

    public GMSSLSocket(GMSSLContextSpi context, InetAddress host, int port) throws IOException {
        super(host, port);
        this.context = context;
        remoteHost = host.getHostName();
        if (remoteHost == null) {
            remoteHost = host.getHostAddress();
        }
        this.connection = new ClientConnectionContext(context, this);
        ensureConnect();
    }

    public GMSSLSocket(GMSSLContextSpi context, Socket socket, String host, int port, boolean autoClose) throws IOException {
        underlyingSocket = socket;
        remoteHost = host;
        this.autoClose = autoClose;
        this.context = context;
        this.connection = new ClientConnectionContext(context, this);
        ensureConnect();
    }

    public GMSSLSocket(GMSSLContextSpi context, String host, int port, InetAddress localAddr, int localPort) throws IOException {
        bind(new InetSocketAddress(localAddr, localPort));
        SocketAddress socketAddress = host != null ? new InetSocketAddress(host, port) :
               new InetSocketAddress(InetAddress.getByName(null), port);
        remoteHost = host;
        this.context = context;
        this.connection = new ClientConnectionContext(context, this);
        connect(socketAddress, 0);
        ensureConnect();
    }

    public GMSSLSocket(GMSSLContextSpi context, InetAddress host, int port, InetAddress localAddress, int localPort) throws IOException {
        bind(new InetSocketAddress(localAddress, localPort));
        SocketAddress socketAddress = new InetSocketAddress(host, port);
        remoteHost = host.getHostName();
        if (remoteHost == null) {
            remoteHost = host.getHostAddress();
        }
        this.context = context;
        this.connection = new ClientConnectionContext(context, this);
        connect(socketAddress, 0);
        ensureConnect();
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
    }

    @Override
    public boolean getEnableSessionCreation() {
        return connection.sslConfig.enableSessionCreation;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        connection.sslConfig.enableSessionCreation = flag;
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return CipherSuite.namesOf(connection.sslConfig.enabledCipherSuites);
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        if (suites == null || suites.length == 0) {
            throw new IllegalArgumentException();
        }
        for (int i = 0; i < suites.length; i++) {
            if (CipherSuite.forName(suites[i]) == null) {
                throw new IllegalArgumentException("unsupported suite: " + suites[i]);
            }
        }

        List<CipherSuite> cipherSuites = new ArrayList<CipherSuite>(suites.length);
        for (int i = 0; i < suites.length; i++) {
            CipherSuite suite = CipherSuite.forName(suites[i]);
            cipherSuites.add(suite);
        }

        connection.sslConfig.setEnabledCipherSuites(cipherSuites);
        connection.session.setEnabledSuites(connection.sslConfig.enabledCipherSuites);
    }

    @Override
    public String[] getEnabledProtocols() {
        return ProtocolVersion.toStringArray(connection.sslConfig.enabledProtocols);
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        if (protocols == null || protocols.length == 0) {
            throw new IllegalArgumentException();
        }

        connection.sslConfig.setEnabledProtocols(ProtocolVersion.namesOf(protocols));
        connection.session.setEnabledProtocols(connection.sslConfig.enabledProtocols);
    }

    @Override
    public boolean getNeedClientAuth() {
        return (connection.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED);
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        connection.sslConfig.clientAuthType = (need ? ClientAuthType.CLIENT_AUTH_REQUIRED : ClientAuthType.CLIENT_AUTH_NONE);
    }

    @Override
    public SSLSession getSession() {
        return connection.session;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return CipherSuite.namesOf(context.getSupportedCipherSuites());
    }

    @Override
    public String[] getSupportedProtocols() {
        return ProtocolVersion.toStringArray(context.getSupportedProtocolVersions());
    }

    @Override
    public boolean getUseClientMode() {
        return clientMode;
    }

    @Override
    public void setUseClientMode(boolean mode) {
        clientMode = mode;
    }

    @Override
    public boolean getWantClientAuth() {
        return (connection.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUESTED);
    }

    @Override
    public void setWantClientAuth(boolean want) {
        connection.sslConfig.clientAuthType =
                (want ? ClientAuthType.CLIENT_AUTH_REQUESTED :
                        ClientAuthType.CLIENT_AUTH_NONE);
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
    }

    @Override
    public void startHandshake() throws IOException {
        if (!isConnected) {
            throw new SocketException("Socket is not connected");
        }

        connection.kickstart();
    }

    public String getPeerHost() {
        return remoteHost;
    }

    public void doneConnect() throws IOException {
        if (underlyingSocket != null) {
            socketIn = underlyingSocket.getInputStream();
            socketOut = underlyingSocket.getOutputStream();
        } else {
            socketIn = super.getInputStream();
            socketOut = super.getOutputStream();
        }
        recordStream = new RecordStream(socketIn, socketOut);
        this.isConnected = true;
    }

    private void ensureConnect() throws IOException {
        if (underlyingSocket != null) {
            if (!underlyingSocket.isConnected()) {
                underlyingSocket.connect(this.getRemoteSocketAddress());
            }
        } else {
            if (!this.isConnected()) {
                SocketAddress socketAddress = new InetSocketAddress(remoteHost, port);
                connect(socketAddress);
            }
        }
        this.doneConnect();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        if (isClosed()) {
            throw new SocketException("Socket is closed");
        }

        if (!isConnected) {
            throw new SocketException("Socket is not connected");
        }

        return appOutput;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        if (isClosed()) {
            throw new SocketException("Socket is closed");
        }

        if (!isConnected) {
            throw new SocketException("Socket is not connected");
        }

        return appInput;
    }

    private class AppDataInputStream extends InputStream {

        private byte[] cacheBuffer = null;
        private int cachePos = 0;

        public AppDataInputStream() {}

        @Override
        public int read() throws IOException {
            byte[] buf = new byte[1];
            int ret = read(buf, 0, 1);
            return ret < 0 ? -1 : buf[0] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (b == null) {
                throw new NullPointerException("the target buffer is null");
            }

            if (len == 0) {
                return 0;
            }

            if (!connection.isNegotiated) {
                startHandshake();
            }

            int length;
            if (cacheBuffer != null) {
                length = Math.min(cacheBuffer.length - cachePos, len);
                System.arraycopy(cacheBuffer, cachePos, b, off, length);

                cachePos += length;
                if (cachePos >= cacheBuffer.length) {
                    cacheBuffer = null;
                    cachePos = 0;
                }
            } else {
                Record record = recordStream.read(true);
                length = Math.min(record.fragment.length, len);
                System.arraycopy(record.fragment, 0, b, off, length);
                if (length < record.fragment.length) {
                    cacheBuffer = record.fragment;
                    cachePos = len;
                }
            }
            return length;
        }
    }

    private class AppDataOutputStream extends OutputStream {
        private static final int MAX_PLAINTEXT_FRAGMENT = 16320; // 16KB - 64 bytes overhead

        public AppDataOutputStream() {}

        @Override
        public void write(int b) throws IOException {
            write(new byte[]{(byte) b}, 0, 1);
        }

        @Override
        public void write(byte b[], int off, int len) throws IOException {
            if (b == null) {
                throw new NullPointerException();
            } else if ((off < 0) || (off > b.length) || (len < 0) ||
                    ((off + len) > b.length) || ((off + len) < 0)) {
                throw new IndexOutOfBoundsException();
            } else if (len == 0) {
                return;
            }

            if (!connection.isNegotiated) {
                startHandshake();
            }

            ProtocolVersion version = ProtocolVersion.NTLS_1_1;
            int remaining = len;
            int currentOffset = off;

            while (remaining > 0) {
                int fragmentLength = Math.min(remaining, MAX_PLAINTEXT_FRAGMENT);
                byte[] fragment = new byte[fragmentLength];
                System.arraycopy(b, currentOffset, fragment, 0, fragmentLength);

                Record record = new Record(Record.ContentType.APPLICATION_DATA, version, fragment);
                try {
                    recordStream.write(record, true);
                } catch (IOException e) {
                    throw new IOException("Failed to write fragmented record", e);
                }

                currentOffset += fragmentLength;
                remaining -= fragmentLength;
            }
        }

        @Override
        public void flush() throws IOException {
            recordStream.flush();
        }
    }
}
