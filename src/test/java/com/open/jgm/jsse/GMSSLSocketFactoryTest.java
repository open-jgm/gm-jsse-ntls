//package com.open.jgm.jsse;
//
//import com.open.jgm.jsse.simple.GmsslTestMaterialPaths;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.junit.Assert;
//import org.junit.Assume;
//import org.junit.Test;
//
//import java.io.DataInputStream;
//import java.io.DataOutputStream;
//import java.io.IOException;
//import java.io.InputStream;
//import java.io.OutputStream;
//import java.net.InetAddress;
//import java.net.ServerSocket;
//import java.net.Socket;
//import java.nio.charset.StandardCharsets;
//import java.security.KeyManagementException;
//import java.security.KeyStore;
//import java.security.KeyStoreException;
//import java.security.NoSuchAlgorithmException;
//import java.security.cert.CertificateException;
//import java.security.cert.CertificateFactory;
//import java.security.cert.X509Certificate;
//import java.util.concurrent.CountDownLatch;
//import java.util.concurrent.TimeUnit;
//
//import javax.net.ssl.SSLContext;
//import javax.net.ssl.SSLServerSocket;
//import javax.net.ssl.SSLSocket;
//import javax.net.ssl.SSLSocketFactory;
//import javax.net.ssl.TrustManagerFactory;
//
//public class GMSSLSocketFactoryTest {
//
//    private static final String PWD = GmsslTestMaterialPaths.DEFAULT_PWD;
//    private static final String OVSSL_HOST = "sm2only.ovssl.cn";
//    private static final int OVSSL_PORT = 443;
//    private static final String GM_CIPHER = CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3.getName();
//
//    @Test
//    public void createSocketTest() throws Exception {
//        GMSSLContextSpi context = new GMSSLContextSpi();
//        GMSSLSocketFactory factory = new GMSSLSocketFactory(context);
//
//        int port = findFreePort();
//        CountDownLatch acceptReady = new CountDownLatch(1);
//        Thread acceptor = new Thread(() -> {
//            try (ServerSocket ss = new ServerSocket(port, 1, InetAddress.getLoopbackAddress())) {
//                acceptReady.countDown();
//                try (Socket s = ss.accept()) {
//                    // client only checks GMSSLSocket type
//                }
//            } catch (IOException e) {
//                throw new RuntimeException(e);
//            }
//        }, "createSocketTest-accept");
//        acceptor.setDaemon(true);
//        acceptor.start();
//        Assert.assertTrue(acceptReady.await(5, TimeUnit.SECONDS));
//
//        try (Socket plain = new Socket(InetAddress.getLoopbackAddress(), port)) {
//            Socket layered = factory.createSocket(plain, "127.0.0.1", port, false);
//            Assert.assertTrue(layered instanceof GMSSLSocket);
//            layered.close();
//        }
//        acceptor.join(5000);
//    }
//
//    private SSLSocketFactory createTrustOnlyFactory() throws Exception {
//        GmSslProviders.ensureInstalled();
//        GMProvider provider = GmSslProviders.gmProvider();
//        SSLContext sc = SSLContext.getInstance("TLS", provider);
//
//        X509Certificate cert = Helper.loadCertificate("WoTrus-SM2.crt");
//        KeyStore ks = KeyStore.getInstance("JKS");
//        ks.load(null, null);
//        ks.setCertificateEntry("gmca", cert);
//
//        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509", provider);
//        tmf.init(ks);
//        sc.init(null, tmf.getTrustManagers(), null);
//        return sc.getSocketFactory();
//    }
//
//    private static void assumeOvsslReachable() {
//        try (Socket probe = new Socket()) {
//            probe.connect(new java.net.InetSocketAddress(OVSSL_HOST, OVSSL_PORT), 5000);
//        } catch (IOException e) {
//            Assume.assumeNoException("sm2only.ovssl.cn:443 not reachable from this network", e);
//        }
//    }
//
//    private static void configureNtisClientSocket(SSLSocket socket) {
//        socket.setEnabledProtocols(new String[]{"NTLSv1.1"});
//        socket.setEnabledCipherSuites(new String[]{GM_CIPHER});
//    }
//
//    /** Public NTLS endpoint (WoTrus); requires network. */
//    @Test
//    public void createSocketTest2() throws Exception {
//        assumeOvsslReachable();
//        SSLSocketFactory factory = createTrustOnlyFactory();
//        try (SSLSocket socket = (SSLSocket) factory.createSocket(OVSSL_HOST, OVSSL_PORT)) {
//            socket.setTcpNoDelay(true);
//            Assert.assertTrue(socket.getTcpNoDelay());
//            configureNtisClientSocket(socket);
//            socket.startHandshake();
//            OutputStream os = socket.getOutputStream();
//            os.write("hello".getBytes(StandardCharsets.UTF_8));
//            os.flush();
//        }
//    }
//
//    /** Public NTLS endpoint by {@link InetAddress}; requires network. */
//    @Test
//    public void createSocketTest3() throws Exception {
//        assumeOvsslReachable();
//        SSLSocketFactory factory = createTrustOnlyFactory();
//        InetAddress address = InetAddress.getByName(OVSSL_HOST);
//        try (SSLSocket socket = (SSLSocket) factory.createSocket(address, OVSSL_PORT)) {
//            configureNtisClientSocket(socket);
//            socket.startHandshake();
//        }
//    }
//
//    @Test
//    public void createSocketLoopbackHandshakeAndWrite() throws Exception {
//        int port = findFreePort();
//        CountDownLatch ready = new CountDownLatch(1);
//        Thread server = new Thread(() -> {
//            try {
//                runLoopbackServer(port, ready);
//            } catch (Exception e) {
//                throw new RuntimeException(e);
//            }
//        }, "gmssl-factory-test-server");
//        server.setDaemon(true);
//        server.start();
//        Assert.assertTrue(ready.await(30, TimeUnit.SECONDS));
//
//        SSLContext clientCtx = JsseSimpleUtil.createSm2SSLContext(
//                GmsslTestMaterialPaths.clientPfx(), PWD, GmsslTestMaterialPaths.clientCa());
//        try (SSLSocket socket = (SSLSocket) clientCtx.getSocketFactory()
//                .createSocket(InetAddress.getLoopbackAddress(), port)) {
//            configureNtisClientSocket(socket);
//            socket.setTcpNoDelay(true);
//            Assert.assertTrue(socket.getTcpNoDelay());
//            socket.startHandshake();
//            OutputStream os = socket.getOutputStream();
//            os.write("hello".getBytes(StandardCharsets.UTF_8));
//            os.flush();
//        }
//        server.join(TimeUnit.SECONDS.toMillis(30));
//    }
//
//    @Test
//    public void createSocketLoopbackByInetAddress() throws Exception {
//        int port = findFreePort();
//        CountDownLatch ready = new CountDownLatch(1);
//        Thread server = new Thread(() -> {
//            try {
//                runLoopbackServer(port, ready);
//            } catch (Exception e) {
//                throw new RuntimeException(e);
//            }
//        }, "gmssl-factory-test-server-2");
//        server.setDaemon(true);
//        server.start();
//        Assert.assertTrue(ready.await(30, TimeUnit.SECONDS));
//
//        SSLContext clientCtx = JsseSimpleUtil.createSm2SSLContext(
//                GmsslTestMaterialPaths.clientPfx(), PWD, GmsslTestMaterialPaths.clientCa());
//        try (SSLSocket socket = (SSLSocket) clientCtx.getSocketFactory()
//                .createSocket(InetAddress.getLoopbackAddress(), port)) {
//            configureNtisClientSocket(socket);
//            socket.startHandshake();
//        }
//        server.join(TimeUnit.SECONDS.toMillis(30));
//    }
//
//    private static void runLoopbackServer(int port, CountDownLatch ready) throws Exception {
//        SSLContext serverCtx = JsseSimpleUtil.createSm2SSLContext(
//                GmsslTestMaterialPaths.serverPfx(), PWD, GmsslTestMaterialPaths.serverCa());
//        try (SSLServerSocket listen = (SSLServerSocket) serverCtx.getServerSocketFactory()
//                .createServerSocket(port, 1, InetAddress.getLoopbackAddress())) {
//            listen.setNeedClientAuth(true);
//            listen.setEnabledCipherSuites(new String[]{GM_CIPHER});
//            ready.countDown();
//            try (SSLSocket socket = (SSLSocket) listen.accept()) {
//                byte[] buf = new byte[256];
//                int len = new DataInputStream(socket.getInputStream()).read(buf);
//                Assert.assertTrue(len > 0);
//                new DataOutputStream(socket.getOutputStream()).write("ok".getBytes(StandardCharsets.UTF_8));
//            }
//        }
//    }
//
//    private static int findFreePort() throws IOException {
//        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
//            return s.getLocalPort();
//        }
//    }
//
//    @Test
//    public void getDefaultCipherSuitesTest() throws Exception {
//        GmSslProviders.ensureInstalled();
//        Assert.assertArrayEquals(new String[]{GM_CIPHER},
//                createTrustOnlyFactory().getDefaultCipherSuites());
//    }
//
//    @Test
//    public void getSupportedCipherSuitesTest() throws Exception {
//        GmSslProviders.ensureInstalled();
//        Assert.assertArrayEquals(new String[]{GM_CIPHER},
//                createTrustOnlyFactory().getSupportedCipherSuites());
//    }
//}