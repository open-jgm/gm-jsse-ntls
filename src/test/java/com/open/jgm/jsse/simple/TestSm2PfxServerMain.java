package com.open.jgm.jsse.simple;

import com.open.jgm.jsse.CipherSuite;
import com.open.jgm.jsse.JsseSimpleUtil;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.util.Arrays;

public class TestSm2PfxServerMain {

    private static final String PWD = GmsslTestMaterialPaths.DEFAULT_PWD;

    private final int port = 19443;

    public static void main(String[] args) throws Exception {
        TestSm2PfxServerMain server = new TestSm2PfxServerMain();
        SSLServerSocket listenSocket = server.createServerSocket();
        System.out.println("SSLServerSocket start " + server.port);
        while (true) {
            SSLSocket socket = null;
            try {
                socket = (SSLSocket) listenSocket.accept();
                DataInputStream in = new DataInputStream(socket.getInputStream());
                byte[] buf = new byte[8192];
                int len = in.read(buf);
                if (len == -1) {
                    System.out.println("eof");
                } else {
                    System.out.println("received=" + new String(buf, 0, len));
                }
                byte[] resp = "1234im server".getBytes();
                System.out.println("resp=" + Arrays.toString(resp));
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                out.write(resp, 0, resp.length);
                out.flush();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (socket != null) {
                    try {
                        socket.close();
                    } catch (Exception ignored) {
                    }
                }
            }
        }
    }

    private SSLServerSocket createServerSocket() throws Exception {
        SSLContext ctx = JsseSimpleUtil.createSm2SSLContext(
                GmsslTestMaterialPaths.serverPfx(), PWD, GmsslTestMaterialPaths.serverCa());
        SSLServerSocketFactory factory = ctx.getServerSocketFactory();
        SSLServerSocket ss = (SSLServerSocket) factory.createServerSocket(port);
        ss.setNeedClientAuth(true);
        ss.setEnabledCipherSuites(new String[]{CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3.getName()});
        return ss;
    }
}