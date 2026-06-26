package com.open.jgm.jsse;

import com.open.jgm.jsse.Record.ContentType;
import com.open.jgm.jsse.crypto.Crypto;
import com.open.jgm.jsse.handshake.*;
import com.open.jgm.jsse.record.Alert;
import com.open.jgm.jsse.record.ChangeCipherSpec;
import com.open.jgm.jsse.record.Handshake;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Vector;

/**
 * Non-blocking GMSSL/TLCP engine driven by SSLEngine wrap/unwrap calls.
 */
public class GMSSLEngine extends SSLEngine {
    private static final int RECORD_HEADER_SIZE = 5;
    private static final int MAX_PLAINTEXT_FRAGMENT = 16320;
    private static final int MAC_SIZE = 32;

    private final GMSSLContextSpi context;
    private final String peerHost;
    private final int peerPort;
    private final RecordStream recordStream = new RecordStream(null, null);
    private final SecurityParameters securityParameters = new SecurityParameters();
    private final List<Handshake> handshakes = new ArrayList<Handshake>();
    private final GMSSLSession session;

    private SSLConfiguration sslConfig;
    private EngineState state = EngineState.NOT_STARTED;
    private boolean inboundCipherActive;
    private boolean outboundCipherActive;
    private boolean inboundClosed;
    private boolean outboundClosed;
    private boolean closeNotifyReceived;
    private boolean closeNotifySent;
    private boolean failed;
    private boolean finishedStatusPending;
    private byte[] pendingOutbound;
    private int pendingOutboundOffset;
    private byte[] pendingPlaintext;
    private int pendingPlaintextOffset;

    public GMSSLEngine(GMSSLContextSpi context) {
        this(context, null, -1);
    }

    public GMSSLEngine(GMSSLContextSpi context, String peerHost, int peerPort) {
        super(peerHost, peerPort);
        this.context = context;
        this.peerHost = peerHost;
        this.peerPort = peerPort;
        this.sslConfig = new SSLConfiguration(context, true);
        this.session = new GMSSLSession(sslConfig.enabledCipherSuites, sslConfig.enabledProtocols);
        this.session.peerHost = peerHost;
        this.session.peerPort = peerPort;
        this.session.protocol = ProtocolVersion.NTLS_1_1;
        this.session.cipherSuite = CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3;
        this.session.sessionId = new GMSSLSession.ID(new byte[0]);
    }

    @Override
    public synchronized void beginHandshake() throws SSLException {
        if (state != EngineState.NOT_STARTED) {
            return;
        }
        if (outboundClosed) {
            throw new SSLException("engine is closed");
        }
        state = sslConfig.isClientMode ? EngineState.CLIENT_SEND_CLIENT_HELLO : EngineState.SERVER_RECV_CLIENT_HELLO;
    }

    @Override
    public synchronized SSLEngineResult wrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        return wrap(new ByteBuffer[]{src}, 0, 1, dst);
    }

    @Override
    public synchronized SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) throws SSLException {
        checkBufferArray(srcs, offset, length);
        if (dst == null) {
            throw new IllegalArgumentException("destination buffer is null");
        }
        ensureHandshakeStarted();

        int produced = drainPendingOutbound(dst);
        if (hasPendingOutbound()) {
            return result(SSLEngineResult.Status.BUFFER_OVERFLOW, 0, produced);
        }
        if (produced > 0) {
            return result(outboundClosed && closeNotifySent ? SSLEngineResult.Status.CLOSED : SSLEngineResult.Status.OK, 0, produced);
        }

        if (failed) {
            return result(SSLEngineResult.Status.CLOSED, 0, 0);
        }

        if (needsCloseNotify()) {
            queueAlert(Alert.Level.WARNING, Alert.Description.CLOSE_NOTIFY);
            closeNotifySent = true;
            return drainQueuedResult(dst, SSLEngineResult.Status.CLOSED);
        }

        if (isHandshakeWrapState()) {
            produceHandshakeRecord();
            return drainQueuedResult(dst, SSLEngineResult.Status.OK);
        }

        if (state != EngineState.FINISHED) {
            return result(SSLEngineResult.Status.OK, 0, 0);
        }

        if (outboundClosed) {
            return result(SSLEngineResult.Status.CLOSED, 0, 0);
        }

        int appBytes = remaining(srcs, offset, length);
        if (appBytes == 0) {
            return result(SSLEngineResult.Status.OK, 0, 0);
        }

        int fragmentLength = Math.min(appBytes, MAX_PLAINTEXT_FRAGMENT);
        int packetLength = RECORD_HEADER_SIZE + encryptedRecordLength(fragmentLength);
        if (dst.remaining() < packetLength) {
            return result(SSLEngineResult.Status.BUFFER_OVERFLOW, 0, 0);
        }

        byte[] fragment = take(srcs, offset, length, fragmentLength);
        try {
            queueRecord(new Record(ContentType.APPLICATION_DATA, ProtocolVersion.NTLS_1_1, fragment), true);
        } catch (IOException ex) {
            throw new SSLException("encrypt application data failed", ex);
        }
        int appProduced = drainPendingOutbound(dst);
        return result(SSLEngineResult.Status.OK, fragment.length, appProduced);
    }

    @Override
    public synchronized SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        return unwrap(src, new ByteBuffer[]{dst}, 0, 1);
    }

    @Override
    public synchronized SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) throws SSLException {
        checkBufferArray(dsts, offset, length);
        if (src == null) {
            throw new IllegalArgumentException("source buffer is null");
        }
        if (inboundClosed) {
            return result(SSLEngineResult.Status.CLOSED, 0, 0);
        }
        ensureHandshakeStarted();

        int pendingProduced = drainPendingPlaintext(dsts, offset, length);
        if (pendingPlaintext != null) {
            return result(SSLEngineResult.Status.BUFFER_OVERFLOW, 0, pendingProduced);
        }
        if (pendingProduced > 0) {
            return result(SSLEngineResult.Status.OK, 0, pendingProduced);
        }

        if (src.remaining() < RECORD_HEADER_SIZE) {
            return result(SSLEngineResult.Status.BUFFER_UNDERFLOW, 0, 0);
        }

        int pos = src.position();
        int type = src.get(pos) & 0xFF;
        ProtocolVersion version = ProtocolVersion.getInstance(src.get(pos + 1) & 0xFF, src.get(pos + 2) & 0xFF);
        int fragmentLength = (src.get(pos + 3) & 0xFF) << 8 | (src.get(pos + 4) & 0xFF);
        if (fragmentLength > RecordStream.MAX_CIPHERTEXT_SIZE) {
            fail(Alert.Description.RECORD_OVERFLOW, "record exceeds maximum allowed size");
        }
        if (src.remaining() < RECORD_HEADER_SIZE + fragmentLength) {
            return result(SSLEngineResult.Status.BUFFER_UNDERFLOW, 0, 0);
        }

        ((Buffer) src).position(pos + RECORD_HEADER_SIZE);
        byte[] fragment = new byte[fragmentLength];
        src.get(fragment);
        Record record = new Record(ContentType.getInstance(type), version, fragment);
        Record plainRecord = decodeRecord(record);
        int consumed = RECORD_HEADER_SIZE + fragmentLength;

        if (plainRecord.contentType == ContentType.ALERT) {
            return handleAlert(plainRecord, consumed);
        }
        if (plainRecord.contentType == ContentType.CHANGE_CIPHER_SPEC) {
            consumeChangeCipherSpec();
            return result(SSLEngineResult.Status.OK, consumed, 0);
        }
        if (plainRecord.contentType == ContentType.HANDSHAKE) {
            consumeHandshakeRecord(plainRecord);
            return result(SSLEngineResult.Status.OK, consumed, 0);
        }
        if (plainRecord.contentType == ContentType.APPLICATION_DATA) {
            if (state != EngineState.FINISHED) {
                fail(Alert.Description.UNEXPECTED_MESSAGE, "application data received before handshake finished");
            }
            pendingPlaintext = plainRecord.fragment;
            pendingPlaintextOffset = 0;
            int appProduced = drainPendingPlaintext(dsts, offset, length);
            SSLEngineResult.Status status = pendingPlaintext == null ? SSLEngineResult.Status.OK : SSLEngineResult.Status.BUFFER_OVERFLOW;
            return result(status, consumed, appProduced);
        }
        fail(Alert.Description.UNEXPECTED_MESSAGE, "unexpected record type");
        return result(SSLEngineResult.Status.CLOSED, consumed, 0);
    }

    @Override
    public Runnable getDelegatedTask() {
        return null;
    }

    @Override
    public synchronized void closeInbound() throws SSLException {
        if (!closeNotifyReceived) {
            inboundClosed = true;
            throw new SSLException("closing inbound before receiving close_notify");
        }
        inboundClosed = true;
    }

    @Override
    public synchronized boolean isInboundDone() {
        return inboundClosed;
    }

    @Override
    public synchronized void closeOutbound() {
        outboundClosed = true;
    }

    @Override
    public synchronized boolean isOutboundDone() {
        if (!outboundClosed) {
            return false;
        }
        if (state == EngineState.FINISHED && !closeNotifySent) {
            return false;
        }
        return !hasPendingOutbound();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return CipherSuite.namesOf(context.getSupportedCipherSuites());
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return CipherSuite.namesOf(sslConfig.enabledCipherSuites);
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        sslConfig.enabledCipherSuites = CipherSuite.validValuesOf(suites);
        session.enabledSuites = sslConfig.enabledCipherSuites;
    }

    @Override
    public String[] getSupportedProtocols() {
        return ProtocolVersion.toStringArray(context.getSupportedProtocolVersions());
    }

    @Override
    public String[] getEnabledProtocols() {
        return ProtocolVersion.toStringArray(sslConfig.enabledProtocols);
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        sslConfig.enabledProtocols = ProtocolVersion.namesOf(protocols);
        session.enabledProtocols = sslConfig.enabledProtocols;
    }

    @Override
    public SSLSession getSession() {
        return session;
    }

    @Override
    public synchronized SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        SSLEngineResult.HandshakeStatus status = handshakeStatus();
        if (status == SSLEngineResult.HandshakeStatus.FINISHED) {
            finishedStatusPending = false;
        }
        return status;
    }

    @Override
    public synchronized void setUseClientMode(boolean mode) {
        if (state != EngineState.NOT_STARTED) {
            throw new IllegalArgumentException("cannot change mode after handshake starts");
        }
        sslConfig = new SSLConfiguration(context, mode);
        session.enabledSuites = sslConfig.enabledCipherSuites;
        session.enabledProtocols = sslConfig.enabledProtocols;
    }

    @Override
    public boolean getUseClientMode() {
        return sslConfig.isClientMode;
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        sslConfig.clientAuthType = need ? ClientAuthType.CLIENT_AUTH_REQUIRED : ClientAuthType.CLIENT_AUTH_NONE;
    }

    @Override
    public boolean getNeedClientAuth() {
        return sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED;
    }

    @Override
    public void setWantClientAuth(boolean want) {
        sslConfig.clientAuthType = want ? ClientAuthType.CLIENT_AUTH_REQUESTED : ClientAuthType.CLIENT_AUTH_NONE;
    }

    @Override
    public boolean getWantClientAuth() {
        return sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUESTED;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        sslConfig.enableSessionCreation = flag;
    }

    @Override
    public boolean getEnableSessionCreation() {
        return sslConfig.enableSessionCreation;
    }

    private void produceHandshakeRecord() throws SSLException {
        try {
            while (!hasPendingOutbound()) {
                switch (state) {
                    case CLIENT_SEND_CLIENT_HELLO:
                        sendClientHello();
                        state = EngineState.CLIENT_RECV_SERVER_HELLO;
                        return;
                    case CLIENT_SEND_CERTIFICATE:
                        if (needsClientCertificate()) {
                            sendClientCertificate();
                            state = EngineState.CLIENT_SEND_CLIENT_KEY_EXCHANGE;
                            return;
                        }
                        state = EngineState.CLIENT_SEND_CLIENT_KEY_EXCHANGE;
                        break;
                    case CLIENT_SEND_CLIENT_KEY_EXCHANGE:
                        sendClientKeyExchange();
                        state = needsClientCertificate() ? EngineState.CLIENT_SEND_CERTIFICATE_VERIFY : EngineState.CLIENT_SEND_CHANGE_CIPHER_SPEC;
                        return;
                    case CLIENT_SEND_CERTIFICATE_VERIFY:
                        sendCertificateVerify();
                        state = EngineState.CLIENT_SEND_CHANGE_CIPHER_SPEC;
                        return;
                    case CLIENT_SEND_CHANGE_CIPHER_SPEC:
                        queueChangeCipherSpec();
                        outboundCipherActive = true;
                        state = EngineState.CLIENT_SEND_FINISHED;
                        return;
                    case CLIENT_SEND_FINISHED:
                        sendFinished("client finished");
                        state = EngineState.CLIENT_RECV_CHANGE_CIPHER_SPEC;
                        return;
                    case SERVER_SEND_SERVER_HELLO:
                        sendServerHello();
                        state = EngineState.SERVER_SEND_CERTIFICATE;
                        return;
                    case SERVER_SEND_CERTIFICATE:
                        sendServerCertificate();
                        state = EngineState.SERVER_SEND_SERVER_KEY_EXCHANGE;
                        return;
                    case SERVER_SEND_SERVER_KEY_EXCHANGE:
                        sendServerKeyExchange();
                        state = shouldRequestClientCertificate() ? EngineState.SERVER_SEND_CERTIFICATE_REQUEST : EngineState.SERVER_SEND_SERVER_HELLO_DONE;
                        return;
                    case SERVER_SEND_CERTIFICATE_REQUEST:
                        sendCertificateRequest();
                        state = EngineState.SERVER_SEND_SERVER_HELLO_DONE;
                        return;
                    case SERVER_SEND_SERVER_HELLO_DONE:
                        sendServerHelloDone();
                        state = shouldRequestClientCertificate() ? EngineState.SERVER_RECV_CLIENT_CERTIFICATE : EngineState.SERVER_RECV_CLIENT_KEY_EXCHANGE;
                        return;
                    case SERVER_SEND_CHANGE_CIPHER_SPEC:
                        queueChangeCipherSpec();
                        outboundCipherActive = true;
                        state = EngineState.SERVER_SEND_FINISHED;
                        return;
                    case SERVER_SEND_FINISHED:
                        sendFinished("server finished");
                        finishHandshake();
                        return;
                    default:
                        return;
                }
            }
        } catch (SSLException ex) {
            throw ex;
        } catch (IOException ex) {
            fail(Alert.Description.INTERNAL_ERROR, ex.getMessage(), ex);
        }
    }

    private void consumeHandshakeRecord(Record record) throws SSLException {
        try {
            Handshake hs = Handshake.read(new ByteArrayInputStream(record.fragment));
            if (hs == null || hs.type == null) {
                fail(Alert.Description.DECODE_ERROR, "unknown handshake message");
            }
            switch (state) {
                case CLIENT_RECV_SERVER_HELLO:
                    requireHandshakeType(hs, Handshake.Type.SERVER_HELLO);
                    receiveServerHello(hs);
                    state = EngineState.CLIENT_RECV_SERVER_CERTIFICATE;
                    return;
                case CLIENT_RECV_SERVER_CERTIFICATE:
                    requireHandshakeType(hs, Handshake.Type.CERTIFICATE);
                    receiveServerCertificate(hs);
                    state = EngineState.CLIENT_RECV_SERVER_KEY_EXCHANGE;
                    return;
                case CLIENT_RECV_SERVER_KEY_EXCHANGE:
                    requireHandshakeType(hs, Handshake.Type.SERVER_KEY_EXCHANGE);
                    receiveServerKeyExchange(hs);
                    state = EngineState.CLIENT_RECV_CERTIFICATE_REQUEST_OR_DONE;
                    return;
                case CLIENT_RECV_CERTIFICATE_REQUEST_OR_DONE:
                    if (hs.type == Handshake.Type.CERTIFICATE_REQUEST) {
                        sslConfig.clientAuthType = ClientAuthType.CLIENT_AUTH_REQUESTED;
                        handshakes.add(hs);
                        state = EngineState.CLIENT_RECV_SERVER_HELLO_DONE;
                    } else if (hs.type == Handshake.Type.SERVER_HELLO_DONE) {
                        handshakes.add(hs);
                        state = EngineState.CLIENT_SEND_CERTIFICATE;
                    } else {
                        fail(Alert.Description.UNEXPECTED_MESSAGE, "expected certificate_request or server_hello_done");
                    }
                    return;
                case CLIENT_RECV_SERVER_HELLO_DONE:
                    requireHandshakeType(hs, Handshake.Type.SERVER_HELLO_DONE);
                    handshakes.add(hs);
                    state = EngineState.CLIENT_SEND_CERTIFICATE;
                    return;
                case CLIENT_RECV_FINISHED:
                    requireHandshakeType(hs, Handshake.Type.FINISHED);
                    verifyFinished(hs, "server finished");
                    finishHandshake();
                    return;
                case SERVER_RECV_CLIENT_HELLO:
                    requireHandshakeType(hs, Handshake.Type.CLIENT_HELLO);
                    receiveClientHello(hs);
                    state = EngineState.SERVER_SEND_SERVER_HELLO;
                    return;
                case SERVER_RECV_CLIENT_CERTIFICATE:
                    requireHandshakeType(hs, Handshake.Type.CERTIFICATE);
                    receiveClientCertificate(hs);
                    state = EngineState.SERVER_RECV_CLIENT_KEY_EXCHANGE;
                    return;
                case SERVER_RECV_CLIENT_KEY_EXCHANGE:
                    requireHandshakeType(hs, Handshake.Type.CLIENT_KEY_EXCHANGE);
                    receiveClientKeyExchange(hs);
                    state = shouldRequestClientCertificate() ? EngineState.SERVER_RECV_CERTIFICATE_VERIFY : EngineState.SERVER_RECV_CHANGE_CIPHER_SPEC;
                    return;
                case SERVER_RECV_CERTIFICATE_VERIFY:
                    requireHandshakeType(hs, Handshake.Type.CERTIFICATE_VERIFY);
                    receiveCertificateVerify(hs);
                    state = EngineState.SERVER_RECV_CHANGE_CIPHER_SPEC;
                    return;
                case SERVER_RECV_FINISHED:
                    requireHandshakeType(hs, Handshake.Type.FINISHED);
                    verifyFinished(hs, "client finished");
                    handshakes.add(hs);
                    state = EngineState.SERVER_SEND_CHANGE_CIPHER_SPEC;
                    return;
                default:
                    fail(Alert.Description.UNEXPECTED_MESSAGE, "unexpected handshake message");
            }
        } catch (SSLException ex) {
            throw ex;
        } catch (IOException ex) {
            fail(Alert.Description.DECODE_ERROR, ex.getMessage(), ex);
        }
    }

    private void consumeChangeCipherSpec() throws SSLException {
        if (state != EngineState.CLIENT_RECV_CHANGE_CIPHER_SPEC && state != EngineState.SERVER_RECV_CHANGE_CIPHER_SPEC) {
            fail(Alert.Description.UNEXPECTED_MESSAGE, "unexpected change_cipher_spec");
        }
        inboundCipherActive = true;
        state = state == EngineState.CLIENT_RECV_CHANGE_CIPHER_SPEC
                ? EngineState.CLIENT_RECV_FINISHED : EngineState.SERVER_RECV_FINISHED;
    }

    private SSLEngineResult handleAlert(Record record, int consumed) throws SSLException {
        byte[] fragment = record.fragment;
        if (fragment.length < 2) {
            fail(Alert.Description.DECODE_ERROR, "invalid alert");
        }
        Alert.Description description = Alert.Description.getInstance(fragment[1] & 0xFF);
        if (description == Alert.Description.CLOSE_NOTIFY) {
            closeNotifyReceived = true;
            inboundClosed = true;
            if (!outboundClosed) {
                outboundClosed = true;
            }
            return result(SSLEngineResult.Status.CLOSED, consumed, 0);
        }
        if ((fragment[0] & 0xFF) == 2) {
            failed = true;
            inboundClosed = true;
            outboundClosed = true;
            throw new SSLException(description.toString());
        }
        return result(SSLEngineResult.Status.OK, consumed, 0);
    }

    private Record decodeRecord(Record record) throws SSLException {
        if (record.contentType == ContentType.CHANGE_CIPHER_SPEC || !inboundCipherActive) {
            return record;
        }
        try {
            return new Record(record.contentType, record.version, recordStream.decrypt(record));
        } catch (IOException ex) {
            fail(Alert.Description.BAD_RECORD_MAC, "decrypt record failed", ex);
            return record;
        }
    }

    private void sendClientHello() throws IOException {
        byte[] sessionId = new byte[0];
        ClientRandom random = new ClientRandom(unixTime(), secureRandom().generateSeed(28));
        List<CompressionMethod> compressions = new ArrayList<CompressionMethod>(2);
        compressions.add(CompressionMethod.NULL);
        ClientHello ch = new ClientHello(ProtocolVersion.NTLS_1_1, random, sessionId,
                sslConfig.enabledCipherSuites, compressions);
        Handshake hs = new Handshake(Handshake.Type.CLIENT_HELLO, ch);
        queueHandshake(hs, false);
        securityParameters.clientRandom = random.getBytes();
    }

    private void receiveServerHello(Handshake hs) throws IOException {
        ServerHello sh = (ServerHello) hs.body;
        sh.getCompressionMethod();
        session.cipherSuite = sh.getCipherSuite();
        session.peerHost = peerHost;
        session.peerPort = peerPort;
        session.sessionId = new GMSSLSession.ID(sh.getSessionId());
        session.protocol = ProtocolVersion.NTLS_1_1;
        securityParameters.serverRandom = sh.getRandom();
        handshakes.add(hs);
    }

    private void receiveServerCertificate(Handshake hs) throws SSLException {
        Certificate cert = (Certificate) hs.body;
        X509Certificate[] peerCerts = cert.getCertificates();
        X509TrustManager trustManager = context.getTrustManager();
        if (trustManager == null) {
            throw new SSLException("trust manager is not configured");
        }
        try {
            trustManager.checkServerTrusted(peerCerts, session.cipherSuite.getAuthType());
        } catch (CertificateException ex) {
            throw new SSLException("could not verify peer certificate!", ex);
        }
        session.peerCerts = peerCerts;
        session.peerVerified = true;
        handshakes.add(hs);
    }

    private void receiveServerKeyExchange(Handshake hs) throws SSLException {
        ServerKeyExchange ske = (ServerKeyExchange) hs.body;
        X509Certificate signCert = session.peerCerts[0];
        X509Certificate encryptionCert = session.peerCerts[1];
        boolean verified;
        try {
            verified = ske.verify(signCert.getPublicKey(), securityParameters.clientRandom,
                    securityParameters.serverRandom, encryptionCert);
        } catch (Exception ex) {
            throw new SSLException("server key exchange verify fails!", ex);
        }
        if (!verified) {
            throw new SSLException("server key exchange verify fails!");
        }
        handshakes.add(hs);
        securityParameters.encryptionCert = encryptionCert;
    }

    private void sendClientCertificate() throws IOException {
        X509KeyManager keyManager = requireKeyManager();
        X509Certificate[] signCerts = requireCertificateChain(keyManager, "sign");
        X509Certificate[] encCerts = requireCertificateChain(keyManager, "enc");
        Certificate cert = new Certificate(new X509Certificate[]{signCerts[0], encCerts[0]});
        queueHandshake(new Handshake(Handshake.Type.CERTIFICATE, cert), false);
    }

    private void sendClientKeyExchange() throws IOException {
        ByteArrayOutputStream preMaster = new ByteArrayOutputStream();
        preMaster.write(ProtocolVersion.NTLS_1_1.getMajor());
        preMaster.write(ProtocolVersion.NTLS_1_1.getMinor());
        preMaster.write(secureRandom().generateSeed(46));
        byte[] preMasterSecret = preMaster.toByteArray();

        byte[] encryptedPreMasterSecret;
        try {
            encryptedPreMasterSecret = Crypto.encrypt((BCECPublicKey) securityParameters.encryptionCert.getPublicKey(), preMasterSecret);
        } catch (Exception ex) {
            throw new SSLException("encrypt pre master secret failed", ex);
        }
        ClientKeyExchange ckex = new ClientKeyExchange(encryptedPreMasterSecret);
        queueHandshake(new Handshake(Handshake.Type.CLIENT_KEY_EXCHANGE, ckex), false);
        applyKeyBlock(preMasterSecret, true);
    }

    private void sendCertificateVerify() throws IOException {
        byte[] source = Crypto.hash(handshakeBytes());
        PrivateKey key = requireKeyManager().getPrivateKey("sign");
        byte[] signature;
        try {
            signature = Crypto.sign((BCECPrivateKey) key, null, source);
        } catch (Exception ex) {
            throw new SSLException("certificate verify failed", ex);
        }
        queueHandshake(new Handshake(Handshake.Type.CERTIFICATE_VERIFY, new CertificateVerify(signature)), false);
    }

    private void sendServerHello() throws IOException {
        byte[] sessionId = new byte[32];
        secureRandom().nextBytes(sessionId);
        ClientRandom random = new ClientRandom(unixTime(), secureRandom().generateSeed(28));
        CipherSuite cs = CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3;
        session.cipherSuite = cs;
        session.protocol = ProtocolVersion.NTLS_1_1;
        session.sessionId = new GMSSLSession.ID(sessionId);
        ServerHello sh = new ServerHello(ProtocolVersion.NTLS_1_1, random.getBytes(), sessionId, cs, CompressionMethod.NULL);
        securityParameters.serverRandom = sh.getRandom();
        queueHandshake(new Handshake(Handshake.Type.SERVER_HELLO, sh), false);
    }

    private void sendServerCertificate() throws IOException {
        X509KeyManager keyManager = requireKeyManager();
        X509Certificate[] signCerts = requireCertificateChain(keyManager, "sign");
        X509Certificate[] encCerts = requireCertificateChain(keyManager, "enc");
        Certificate cert = new Certificate(new X509Certificate[]{signCerts[0], encCerts[0]});
        queueHandshake(new Handshake(Handshake.Type.CERTIFICATE, cert), false);
    }

    private void sendServerKeyExchange() throws IOException {
        try {
            Signature signature = Signature.getInstance("SM3withSM2", new BouncyCastleProvider());
            signature.setParameter(new SM2ParameterSpec("1234567812345678".getBytes()));
            PrivateKey signKey = requireKeyManager().getPrivateKey("sign");
            signature.initSign(signKey);
            signature.update(securityParameters.clientRandom);
            signature.update(securityParameters.serverRandom);

            X509Certificate[] encryptCerts = requireKeyManager().getCertificateChain("enc");
            byte[] encryptCert = encryptCerts[0].getEncoded();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write((encryptCert.length >>> 16) & 0xff);
            baos.write((encryptCert.length >>> 8) & 0xff);
            baos.write(encryptCert.length & 0xff);
            baos.write(encryptCert);
            signature.update(baos.toByteArray());
            queueHandshake(new Handshake(Handshake.Type.SERVER_KEY_EXCHANGE,
                    new ServerKeyExchange(signature.sign())), false);
        } catch (Exception ex) {
            throw new SSLException("server key exchange signature fails!", ex);
        }
    }

    private void sendCertificateRequest() throws IOException {
        short[] certificateTypes = new short[]{
                ClientCertificateType.ecdsa_sign,
                ClientCertificateType.rsa_sign,
                ClientCertificateType.ibc_params
        };
        List<X500Principal> caSubjects = new ArrayList<X500Principal>();
        X509TrustManager trustManager = context.getTrustManager();
        if (trustManager != null) {
            X509Certificate[] issuers = trustManager.getAcceptedIssuers();
            for (int i = 0; i < issuers.length; i++) {
                caSubjects.add(issuers[i].getSubjectX500Principal());
            }
        }
        Vector<byte[]> authorities = new Vector<byte[]>(caSubjects.size());
        for (int i = 0; i < caSubjects.size(); i++) {
            authorities.add(caSubjects.get(i).getEncoded());
        }
        queueHandshake(new Handshake(Handshake.Type.CERTIFICATE_REQUEST,
                new CertificateRequest(certificateTypes, authorities)), false);
    }

    private void sendServerHelloDone() throws IOException {
        queueHandshake(new Handshake(Handshake.Type.SERVER_HELLO_DONE, new ServerHelloDone()), false);
    }

    private void receiveClientHello(Handshake hs) throws IOException {
        ClientHello ch = (ClientHello) hs.body;
        securityParameters.clientRandom = ch.getClientRandom().getBytes();
        handshakes.add(hs);
    }

    private void receiveClientCertificate(Handshake hs) throws SSLException {
        Certificate cert = (Certificate) hs.body;
        X509Certificate[] peerCerts = cert.getCertificates();
        X509TrustManager trustManager = context.getTrustManager();
        if (trustManager == null) {
            throw new SSLException("trust manager is not configured");
        }
        try {
            trustManager.checkClientTrusted(peerCerts, session.cipherSuite.getAuthType());
        } catch (CertificateException ex) {
            throw new SSLException("could not verify peer certificate!", ex);
        }
        session.peerCerts = peerCerts;
        session.peerVerified = true;
        handshakes.add(hs);
    }

    private void receiveClientKeyExchange(Handshake hs) throws IOException {
        ClientKeyExchange ckex = (ClientKeyExchange) hs.body;
        handshakes.add(hs);
        PrivateKey key = requireKeyManager().getPrivateKey("enc");
        byte[] preMasterSecret;
        try {
            preMasterSecret = Crypto.decrypt((BCECPrivateKey) key, ckex.getEncryptedPreMasterSecret());
        } catch (Exception ex) {
            throw new SSLException("decrypt pre master secret failed", ex);
        }
        applyKeyBlock(preMasterSecret, false);
    }

    private void receiveCertificateVerify(Handshake hs) throws SSLException {
        CertificateVerify cv = (CertificateVerify) hs.body;
        X509Certificate signCert = session.peerCerts[0];
        byte[] source = Crypto.hash(handshakeBytes());
        boolean verified;
        try {
            verified = Crypto.verify((BCECPublicKey) signCert.getPublicKey(), null, source, cv.getSignature());
        } catch (Exception ex) {
            throw new SSLException("certificate verify failed", ex);
        }
        if (!verified) {
            throw new SSLException("certificate verify failed");
        }
        handshakes.add(hs);
    }

    private void sendFinished(String label) throws IOException {
        byte[] verifyData = finishedVerifyData(label);
        queueHandshake(new Handshake(Handshake.Type.FINISHED, new Finished(verifyData)), true);
    }

    private void verifyFinished(Handshake hs, String label) throws SSLException {
        byte[] verifyData = finishedVerifyData(label);
        Finished finished = (Finished) hs.body;
        byte[] actual;
        try {
            actual = finished.getBytes();
        } catch (IOException ex) {
            throw new SSLException("read verify data failed", ex);
        }
        if (!Arrays.equals(actual, verifyData)) {
            fail(Alert.Description.HANDSHAKE_FAILURE, "finished verify data mismatch");
        }
    }

    private byte[] finishedVerifyData(String label) throws SSLException {
        try {
            return Crypto.prf(securityParameters.masterSecret, label.getBytes(), Crypto.hash(handshakeBytes()), 12);
        } catch (Exception ex) {
            throw new SSLException("caculate verify data failed", ex);
        }
    }

    private void applyKeyBlock(byte[] preMasterSecret, boolean client) throws SSLException {
        try {
            ByteArrayOutputStream seedOut = new ByteArrayOutputStream();
            seedOut.write(securityParameters.clientRandom);
            seedOut.write(securityParameters.serverRandom);
            securityParameters.masterSecret = Crypto.prf(preMasterSecret, "master secret".getBytes(),
                    seedOut.toByteArray(), preMasterSecret.length);

            ByteArrayOutputStream keyBlockSeed = new ByteArrayOutputStream();
            keyBlockSeed.write(securityParameters.serverRandom);
            keyBlockSeed.write(securityParameters.clientRandom);
            byte[] keyBlock = Crypto.prf(securityParameters.masterSecret, "key expansion".getBytes(),
                    keyBlockSeed.toByteArray(), 128);

            byte[] clientMacKey = slice(keyBlock, 0, 32);
            byte[] serverMacKey = slice(keyBlock, 32, 32);
            byte[] clientWriteKey = slice(keyBlock, 64, 16);
            byte[] serverWriteKey = slice(keyBlock, 80, 16);
            byte[] clientWriteIV = slice(keyBlock, 96, 16);
            byte[] serverWriteIV = slice(keyBlock, 112, 16);

            SM4Engine clientEncryptCipher = new SM4Engine();
            clientEncryptCipher.init(true, new KeyParameter(clientWriteKey));
            SM4Engine serverEncryptCipher = new SM4Engine();
            serverEncryptCipher.init(true, new KeyParameter(serverWriteKey));
            SM4Engine clientDecryptCipher = new SM4Engine();
            clientDecryptCipher.init(false, new KeyParameter(clientWriteKey));
            SM4Engine serverDecryptCipher = new SM4Engine();
            serverDecryptCipher.init(false, new KeyParameter(serverWriteKey));

            if (client) {
                recordStream.setEncryptMacKey(clientMacKey);
                recordStream.setDecryptMacKey(serverMacKey);
                recordStream.setWriteCipher(clientEncryptCipher);
                recordStream.setReadCipher(serverDecryptCipher);
                recordStream.setEncryptIV(clientWriteIV);
                recordStream.setDecryptIV(serverWriteIV);
            } else {
                recordStream.setDecryptMacKey(clientMacKey);
                recordStream.setEncryptMacKey(serverMacKey);
                recordStream.setReadCipher(clientDecryptCipher);
                recordStream.setWriteCipher(serverEncryptCipher);
                recordStream.setDecryptIV(clientWriteIV);
                recordStream.setEncryptIV(serverWriteIV);
            }
        } catch (Exception ex) {
            throw new SSLException("caculate key block failed", ex);
        }
    }

    private void queueHandshake(Handshake hs, boolean encrypted) throws IOException {
        Record record = new Record(ContentType.HANDSHAKE, ProtocolVersion.NTLS_1_1, hs.getBytes());
        queueRecord(record, encrypted);
        handshakes.add(hs);
    }

    private void queueChangeCipherSpec() throws IOException {
        queueRecord(new Record(ContentType.CHANGE_CIPHER_SPEC, ProtocolVersion.NTLS_1_1,
                new ChangeCipherSpec().getBytes()), false);
    }

    private void queueAlert(Alert.Level level, Alert.Description description) throws SSLException {
        try {
            queueRecord(new Record(ContentType.ALERT, ProtocolVersion.NTLS_1_1,
                    new Alert(level, description).getBytes()), outboundCipherActive);
        } catch (IOException ex) {
            throw new SSLException("queue alert failed", ex);
        }
    }

    private void queueRecord(Record record, boolean encrypted) throws IOException {
        Record out = encrypted ? recordStream.encrypt(record) : record;
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        bytes.write(out.contentType.getValue());
        bytes.write(out.version.getMajor());
        bytes.write(out.version.getMinor());
        bytes.write(out.fragment.length >>> 8 & 0xFF);
        bytes.write(out.fragment.length & 0xFF);
        bytes.write(out.fragment);
        queueBytes(bytes.toByteArray());
    }

    private void queueBytes(byte[] bytes) {
        if (bytes.length == 0) {
            return;
        }
        if (!hasPendingOutbound()) {
            pendingOutbound = bytes;
            pendingOutboundOffset = 0;
            return;
        }
        byte[] existing = new byte[pendingOutbound.length - pendingOutboundOffset];
        System.arraycopy(pendingOutbound, pendingOutboundOffset, existing, 0, existing.length);
        byte[] combined = new byte[existing.length + bytes.length];
        System.arraycopy(existing, 0, combined, 0, existing.length);
        System.arraycopy(bytes, 0, combined, existing.length, bytes.length);
        pendingOutbound = combined;
        pendingOutboundOffset = 0;
    }

    private SSLEngineResult drainQueuedResult(ByteBuffer dst, SSLEngineResult.Status emptyStatus) throws SSLException {
        if (!dst.hasRemaining()) {
            return result(SSLEngineResult.Status.BUFFER_OVERFLOW, 0, 0);
        }
        int produced = drainPendingOutbound(dst);
        SSLEngineResult.Status status = hasPendingOutbound() ? SSLEngineResult.Status.BUFFER_OVERFLOW : emptyStatus;
        return result(status, 0, produced);
    }

    private int drainPendingOutbound(ByteBuffer dst) {
        if (!hasPendingOutbound()) {
            return 0;
        }
        int copyLength = Math.min(dst.remaining(), pendingOutbound.length - pendingOutboundOffset);
        if (copyLength == 0) {
            return 0;
        }
        dst.put(pendingOutbound, pendingOutboundOffset, copyLength);
        pendingOutboundOffset += copyLength;
        if (pendingOutboundOffset >= pendingOutbound.length) {
            pendingOutbound = null;
            pendingOutboundOffset = 0;
        }
        return copyLength;
    }

    private boolean hasPendingOutbound() {
        return pendingOutbound != null && pendingOutboundOffset < pendingOutbound.length;
    }

    private boolean needsCloseNotify() {
        return outboundClosed && state == EngineState.FINISHED && !closeNotifySent;
    }

    private void finishHandshake() {
        state = EngineState.FINISHED;
        finishedStatusPending = true;
    }

    private boolean needsClientCertificate() {
        return sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUESTED
                || sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED;
    }

    private boolean shouldRequestClientCertificate() {
        return sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUESTED
                || sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED;
    }

    private boolean isHandshakeWrapState() {
        switch (state) {
            case CLIENT_SEND_CLIENT_HELLO:
            case CLIENT_SEND_CERTIFICATE:
            case CLIENT_SEND_CLIENT_KEY_EXCHANGE:
            case CLIENT_SEND_CERTIFICATE_VERIFY:
            case CLIENT_SEND_CHANGE_CIPHER_SPEC:
            case CLIENT_SEND_FINISHED:
            case SERVER_SEND_SERVER_HELLO:
            case SERVER_SEND_CERTIFICATE:
            case SERVER_SEND_SERVER_KEY_EXCHANGE:
            case SERVER_SEND_CERTIFICATE_REQUEST:
            case SERVER_SEND_SERVER_HELLO_DONE:
            case SERVER_SEND_CHANGE_CIPHER_SPEC:
            case SERVER_SEND_FINISHED:
                return true;
            default:
                return false;
        }
    }

    private boolean isHandshakeUnwrapState() {
        switch (state) {
            case CLIENT_RECV_SERVER_HELLO:
            case CLIENT_RECV_SERVER_CERTIFICATE:
            case CLIENT_RECV_SERVER_KEY_EXCHANGE:
            case CLIENT_RECV_CERTIFICATE_REQUEST_OR_DONE:
            case CLIENT_RECV_SERVER_HELLO_DONE:
            case CLIENT_RECV_CHANGE_CIPHER_SPEC:
            case CLIENT_RECV_FINISHED:
            case SERVER_RECV_CLIENT_HELLO:
            case SERVER_RECV_CLIENT_CERTIFICATE:
            case SERVER_RECV_CLIENT_KEY_EXCHANGE:
            case SERVER_RECV_CERTIFICATE_VERIFY:
            case SERVER_RECV_CHANGE_CIPHER_SPEC:
            case SERVER_RECV_FINISHED:
                return true;
            default:
                return false;
        }
    }

    private SSLEngineResult.HandshakeStatus handshakeStatus() {
        if (finishedStatusPending) {
            return SSLEngineResult.HandshakeStatus.FINISHED;
        }
        if (hasPendingOutbound() || needsCloseNotify()) {
            return SSLEngineResult.HandshakeStatus.NEED_WRAP;
        }
        if (state == EngineState.NOT_STARTED || state == EngineState.FINISHED || state == EngineState.FAILED) {
            return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        }
        if (isHandshakeWrapState()) {
            return SSLEngineResult.HandshakeStatus.NEED_WRAP;
        }
        if (isHandshakeUnwrapState()) {
            return SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
        }
        return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
    }

    private SSLEngineResult result(SSLEngineResult.Status status, int consumed, int produced) {
        SSLEngineResult.HandshakeStatus handshakeStatus = handshakeStatus();
        if (handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED) {
            finishedStatusPending = false;
        }
        return new SSLEngineResult(status, handshakeStatus, consumed, produced);
    }

    private void ensureHandshakeStarted() throws SSLException {
        if (state == EngineState.NOT_STARTED) {
            beginHandshake();
        }
    }

    private void requireHandshakeType(Handshake hs, Handshake.Type type) throws SSLException {
        if (hs.type != type) {
            fail(Alert.Description.UNEXPECTED_MESSAGE, "unexpected handshake message");
        }
    }

    private void fail(Alert.Description description, String message) throws SSLException {
        fail(description, message, null);
    }

    private void fail(Alert.Description description, String message, Throwable cause) throws SSLException {
        failed = true;
        inboundClosed = true;
        state = EngineState.FAILED;
        try {
            if (!outboundClosed) {
                queueAlert(Alert.Level.FATAL, description);
            }
        } catch (SSLException ignored) {
        }
        SSLException exception = cause == null ? new SSLException(message) : new SSLException(message, cause);
        throw exception;
    }

    private byte[] handshakeBytes() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < handshakes.size(); i++) {
            try {
                out.write(handshakes.get(i).getBytes());
            } catch (IOException ignored) {
            }
        }
        return out.toByteArray();
    }

    private X509KeyManager requireKeyManager() throws SSLException {
        X509KeyManager keyManager = context.getKeyManager();
        if (keyManager == null) {
            throw new SSLException("key manager is not configured");
        }
        return keyManager;
    }

    private X509Certificate[] requireCertificateChain(X509KeyManager keyManager, String alias) throws SSLException {
        X509Certificate[] chain = keyManager.getCertificateChain(alias);
        if (chain == null || chain.length == 0 || chain[0] == null) {
            fail(Alert.Description.HANDSHAKE_FAILURE, "certificate chain is not configured: " + alias);
        }
        return chain;
    }

    private SecureRandom secureRandom() {
        SecureRandom random = context.getSecureRandom();
        return random == null ? new SecureRandom() : random;
    }

    private static int unixTime() {
        return (int) (System.currentTimeMillis() / 1000L);
    }

    private static byte[] slice(byte[] bytes, int offset, int length) {
        byte[] out = new byte[length];
        System.arraycopy(bytes, offset, out, 0, length);
        return out;
    }

    private int drainPendingPlaintext(ByteBuffer[] dsts, int offset, int length) {
        if (pendingPlaintext == null) {
            return 0;
        }
        int produced = 0;
        while (pendingPlaintextOffset < pendingPlaintext.length) {
            ByteBuffer dst = nextWritable(dsts, offset, length);
            if (dst == null) {
                break;
            }
            int copyLength = Math.min(dst.remaining(), pendingPlaintext.length - pendingPlaintextOffset);
            dst.put(pendingPlaintext, pendingPlaintextOffset, copyLength);
            pendingPlaintextOffset += copyLength;
            produced += copyLength;
        }
        if (pendingPlaintextOffset >= pendingPlaintext.length) {
            pendingPlaintext = null;
            pendingPlaintextOffset = 0;
        }
        return produced;
    }

    private ByteBuffer nextWritable(ByteBuffer[] buffers, int offset, int length) {
        for (int i = offset; i < offset + length; i++) {
            if (buffers[i] == null) {
                throw new IllegalArgumentException("buffer is null");
            }
            if (buffers[i].hasRemaining()) {
                return buffers[i];
            }
        }
        return null;
    }

    private static int remaining(ByteBuffer[] srcs, int offset, int length) {
        int total = 0;
        for (int i = offset; i < offset + length; i++) {
            total += srcs[i].remaining();
        }
        return total;
    }

    private static byte[] take(ByteBuffer[] srcs, int offset, int length, int count) {
        byte[] out = new byte[count];
        int copied = 0;
        for (int i = offset; i < offset + length && copied < count; i++) {
            int copyLength = Math.min(srcs[i].remaining(), count - copied);
            srcs[i].get(out, copied, copyLength);
            copied += copyLength;
        }
        return out;
    }

    private static int encryptedRecordLength(int plaintextLength) {
        int total = RecordStream.BLOCK_SIZE + plaintextLength + MAC_SIZE + 1;
        int paddingLength = RecordStream.BLOCK_SIZE - total % RecordStream.BLOCK_SIZE;
        return total + paddingLength;
    }

    private static void checkBufferArray(ByteBuffer[] buffers, int offset, int length) {
        if (buffers == null) {
            throw new IllegalArgumentException("buffer array is null");
        }
        if (offset < 0 || length < 0 || offset > buffers.length - length) {
            throw new IndexOutOfBoundsException();
        }
        for (int i = offset; i < offset + length; i++) {
            if (buffers[i] == null) {
                throw new IllegalArgumentException("buffer is null");
            }
        }
    }

    private enum EngineState {
        NOT_STARTED,
        CLIENT_SEND_CLIENT_HELLO,
        CLIENT_RECV_SERVER_HELLO,
        CLIENT_RECV_SERVER_CERTIFICATE,
        CLIENT_RECV_SERVER_KEY_EXCHANGE,
        CLIENT_RECV_CERTIFICATE_REQUEST_OR_DONE,
        CLIENT_RECV_SERVER_HELLO_DONE,
        CLIENT_SEND_CERTIFICATE,
        CLIENT_SEND_CLIENT_KEY_EXCHANGE,
        CLIENT_SEND_CERTIFICATE_VERIFY,
        CLIENT_SEND_CHANGE_CIPHER_SPEC,
        CLIENT_SEND_FINISHED,
        CLIENT_RECV_CHANGE_CIPHER_SPEC,
        CLIENT_RECV_FINISHED,
        SERVER_RECV_CLIENT_HELLO,
        SERVER_SEND_SERVER_HELLO,
        SERVER_SEND_CERTIFICATE,
        SERVER_SEND_SERVER_KEY_EXCHANGE,
        SERVER_SEND_CERTIFICATE_REQUEST,
        SERVER_SEND_SERVER_HELLO_DONE,
        SERVER_RECV_CLIENT_CERTIFICATE,
        SERVER_RECV_CLIENT_KEY_EXCHANGE,
        SERVER_RECV_CERTIFICATE_VERIFY,
        SERVER_RECV_CHANGE_CIPHER_SPEC,
        SERVER_RECV_FINISHED,
        SERVER_SEND_CHANGE_CIPHER_SPEC,
        SERVER_SEND_FINISHED,
        FINISHED,
        FAILED
    }
}
