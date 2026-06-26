package com.open.jgm.jsse.protocol;

import com.open.jgm.jsse.*;
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

import javax.net.ssl.SSLException;
import javax.net.ssl.X509KeyManager;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ClientConnectionContext extends ConnectionContext {

    public GMSSLSession.ID sessionId;
    public int peerPort;
    public boolean peerVerified;
    public String peerHost;
    public CipherSuite cipherSuite;
    public X509Certificate[] peerCerts;
    private SecurityParameters securityParameters = new SecurityParameters();
    private List<Handshake> handshakes = new ArrayList<Handshake>();
    public ClientConnectionContext(GMSSLContextSpi context, GMSSLSocket socket) {
        super(context, socket, new SSLConfiguration(context, true));
    }
    public ClientConnectionContext(GMSSLContextSpi context, GMSSLSocket socket, SSLConfiguration sslConfig) {
        super(context, socket, sslConfig);
    }

    public void kickstart() throws IOException {
        // send ClientHello
        sendClientHello();

        // recive ServerHello
        receiveServerHello();

        // recive ServerCertificate
        receiveServerCertificate();

        // recive ServerKeyExchange
        receiveServerKeyExchange();

        Record rc = socket.recordStream.read();
        if (rc.contentType != ContentType.HANDSHAKE) {
            Alert alert = new Alert(Alert.Level.FATAL, Alert.Description.UNEXPECTED_MESSAGE);
            throw new AlertException(alert, true);
        }

        Handshake cf = Handshake.read(new ByteArrayInputStream(rc.fragment));
        handshakes.add(cf);
        if (cf.type == Handshake.Type.CERTIFICATE_REQUEST) {
            this.sslConfig.clientAuthType = ClientAuthType.CLIENT_AUTH_REQUESTED;

            // recive ServerHelloDone
            receiveServerHelloDone();
        } else if (cf.type == Handshake.Type.SERVER_HELLO_DONE) {
            // recive ServerHelloDone
            // nothing to do
        }

        if (this.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUESTED) {
            // send Certificate
            sendClientCertificate();
        }

        // send ClientKeyExchange
        sendClientKeyExchange();

        if (this.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUESTED) {
            // send CertificateVerify
            sendCertificateVerify();
        }

        // send ChangeCipherSpec
        sendChangeCipherSpec();

        // send Finished
        sendFinished();

        // recive ChangeCipherSpec
        receiveChangeCipherSpec();

        // recive finished
        receiveFinished();

        this.isNegotiated = true;
    }

    private void receiveFinished() throws IOException {
        Record rc = socket.recordStream.read(true);
        Handshake hs = Handshake.read(new ByteArrayInputStream(rc.fragment));
        Finished finished = (Finished) hs.body;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Handshake handshake : handshakes) {
            out.write(handshake.getBytes());
        }
        // SM3(handshake_mesages)
        byte[] seed = Crypto.hash(out.toByteArray());
        byte[] verifyData;
        try {
            // PRF(master_secret，finished_label，SM3(handshake_mesages))[0.11]
            verifyData = Crypto.prf(securityParameters.masterSecret, "server finished".getBytes(), seed, 12);
        } catch (Exception e) {
            throw new SSLException("caculate verify data failed", e);
        }

        if (!Arrays.equals(finished.getBytes(), verifyData)) {
            Alert alert = new Alert(Alert.Level.FATAL, Alert.Description.HANDSHAKE_FAILURE);
            throw new AlertException(alert, true);
        }
    }

    private void receiveChangeCipherSpec() throws IOException {
        Record rc = socket.recordStream.read();
        ChangeCipherSpec ccs = ChangeCipherSpec.read(new ByteArrayInputStream(rc.fragment));
    }

    private void sendFinished() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Handshake handshake : handshakes) {
            out.write(handshake.getBytes());
        }
        // SM3(handshake_mesages)
        byte[] seed = Crypto.hash(out.toByteArray());
        byte[] verifyData;
        try {
            // PRF(master_secret，finished_label，SM3(handshake_mesages))[0.11]
            verifyData = Crypto.prf(securityParameters.masterSecret, "client finished".getBytes(), seed, 12);
        } catch (Exception e) {
            throw new SSLException("caculate verify data failed", e);
        }

        Finished finished = new Finished(verifyData);
        Handshake hs = new Handshake(Handshake.Type.FINISHED, finished);
        // System.out.println(hs.getBytes().length);
        Record rc = new Record(ContentType.HANDSHAKE, version, hs.getBytes());
        socket.recordStream.write(rc, true);
        handshakes.add(hs);
    }

    private void sendChangeCipherSpec() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        Record rc = new Record(ContentType.CHANGE_CIPHER_SPEC, version, new ChangeCipherSpec().getBytes());
        socket.recordStream.write(rc);
    }

    private void sendCertificateVerify() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Handshake handshake : handshakes) {
            out.write(handshake.getBytes());
        }
        // byte[] signature = Crypto.hash(out.toByteArray());
        byte[] source = Crypto.hash(out.toByteArray());
        PrivateKey key = sslContext.getKeyManager().getPrivateKey("sign");
        byte[] signature = Crypto.sign((BCECPrivateKey) key,null,source);
        CertificateVerify cv = new CertificateVerify(signature);
        Handshake hs = new Handshake(Handshake.Type.CERTIFICATE_VERIFY, cv);
        Record rc = new Record(ContentType.HANDSHAKE, version, hs.getBytes());
        socket.recordStream.write(rc);
        handshakes.add(hs);
    }

    private void sendClientKeyExchange() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        // 计算 preMasterSecret
        ByteArrayOutputStream ba = new ByteArrayOutputStream();
        ba.write(version.getMajor());
        ba.write(version.getMinor());
        ba.write(sslContext.getSecureRandom().generateSeed(46));
        byte[] preMasterSecret = ba.toByteArray();

        // 计算 encryptedPreMasterSecret
        byte[] encryptedPreMasterSecret;
        try {
            encryptedPreMasterSecret = Crypto.encrypt((BCECPublicKey) securityParameters.encryptionCert.getPublicKey(), preMasterSecret);
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }

        ClientKeyExchange ckex = new ClientKeyExchange(encryptedPreMasterSecret);
        Handshake hs = new Handshake(Handshake.Type.CLIENT_KEY_EXCHANGE, ckex);
        Record rc = new Record(ContentType.HANDSHAKE, version, hs.getBytes());
        socket.recordStream.write(rc);
        handshakes.add(hs);

        KeySchedule.Material material = KeySchedule.derive(preMasterSecret,
                securityParameters.clientRandom, securityParameters.serverRandom);
        securityParameters.masterSecret = material.getMasterSecret();
        KeySchedule.applyClientWrite(socket.recordStream, material);
    }

    private void sendClientCertificate() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        X509KeyManager km = sslContext.getKeyManager();
        X509Certificate[] signCerts = km.getCertificateChain("sign");
        X509Certificate[] encCerts = km.getCertificateChain("enc");
        Certificate cert = new Certificate(new X509Certificate[] {
            signCerts[0],
            encCerts[0]
        });
        Handshake hs = new Handshake(Handshake.Type.CERTIFICATE, cert);
        Record rc = new Record(ContentType.HANDSHAKE, version, hs.getBytes());
        handshakes.add(hs);
        socket.recordStream.write(rc);
    }

    private void receiveServerHelloDone() throws IOException {
        Record rc = socket.recordStream.read();
        Handshake shdf = Handshake.read(new ByteArrayInputStream(rc.fragment));
        handshakes.add(shdf);
    }

    private void receiveServerKeyExchange() throws IOException {
        Record rc = socket.recordStream.read();
        Handshake skef = Handshake.read(new ByteArrayInputStream(rc.fragment));
        ServerKeyExchange ske = (ServerKeyExchange) skef.body;
        // signature cert
        X509Certificate signCert = session.peerCerts[0];
        // encryption cert
        X509Certificate encryptionCert = session.peerCerts[1];
        // verify the signature
        boolean verified = false;

        try {
            verified = ske.verify(signCert.getPublicKey(), securityParameters.clientRandom,
                    securityParameters.serverRandom, encryptionCert);
        } catch (Exception e2) {
            throw new SSLException("server key exchange verify fails!", e2);
        }

        if (!verified) {
            throw new SSLException("server key exchange verify fails!");
        }

        handshakes.add(skef);
        securityParameters.encryptionCert = encryptionCert;
    }

    private void receiveServerCertificate() throws IOException {
        Record rc = socket.recordStream.read();
        Handshake cf = Handshake.read(new ByteArrayInputStream(rc.fragment));
        Certificate cert = (Certificate) cf.body;
        X509Certificate[] peerCerts = cert.getCertificates();
        try {
            sslContext.getTrustManager().checkServerTrusted(peerCerts, session.cipherSuite.getAuthType());
        } catch (CertificateException e) {
            throw new SSLException("could not verify peer certificate!", e);
        }
        session.peerCerts = peerCerts;
        session.peerVerified = true;
        handshakes.add(cf);
    }

    private void receiveServerHello() throws IOException {
        Record rc = socket.recordStream.read();
        if (rc.contentType != ContentType.HANDSHAKE) {
            Alert alert = new Alert(Alert.Level.FATAL, Alert.Description.UNEXPECTED_MESSAGE);
            throw new AlertException(alert, true);
        }
        Handshake hsf = Handshake.read(new ByteArrayInputStream(rc.fragment));
        ServerHello sh = (ServerHello) hsf.body;
        HandshakeNegotiator.Negotiated negotiated;
        try {
            negotiated = HandshakeNegotiator.validateServerHello(sslConfig.enabledProtocols,
                    sslConfig.enabledCipherSuites, sh.getProtocolVersion(), sh.getCipherSuite(),
                    sh.getCompressionMethod());
        } catch (HandshakeNegotiator.NegotiationException ex) {
            throw new AlertException(new Alert(Alert.Level.FATAL, ex.getDescription()), true);
        }
        session.cipherSuite = negotiated.getCipherSuite();
        session.setProtocol(negotiated.getProtocolVersion());
        session.peerHost = socket.getPeerHost();
        session.peerPort = socket.getPort();
        session.sessionId = new GMSSLSession.ID(sh.getSessionId());
        handshakes.add(hsf);
        securityParameters.serverRandom = sh.getRandom();
    }

    private void sendClientHello() throws IOException {
        byte[] sessionId = new byte[0];
        int gmtUnixTime = (int) (System.currentTimeMillis() / 1000L);
        ClientRandom random = new ClientRandom(gmtUnixTime, sslContext.getSecureRandom().generateSeed(28));
        List<CipherSuite> suites = sslConfig.enabledCipherSuites;
        List<CompressionMethod> compressions = new ArrayList<CompressionMethod>(2);
        compressions.add(CompressionMethod.NULL);
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        ClientHello ch = new ClientHello(version, random, sessionId, suites, compressions);
        Handshake hs = new Handshake(Handshake.Type.CLIENT_HELLO, ch);
        Record rc = new Record(ContentType.HANDSHAKE, version, hs.getBytes());
        socket.recordStream.write(rc);
        handshakes.add(hs);
        securityParameters.clientRandom = random.getBytes();
    }

}
