package com.open.jgm.jsse.simple;

import com.open.jgm.jsse.CipherSuite;
import com.open.jgm.jsse.JsseSimpleUtil;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;

public class TestSm2PfxClientMain {

    private static final String PWD = GmsslTestMaterialPaths.DEFAULT_PWD;

    private final String addr = "192.168.100.22";
    private final int port = 19443;

    public static void main(String[] args) throws Exception {
        TestSm2PfxClientMain client = new TestSm2PfxClientMain();
        try (SSLSocket socket = client.createSocket()) {
            socket.setEnabledCipherSuites(new String[]{CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3.getName()});
            socket.setTcpNoDelay(true);
            socket.startHandshake();

            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.write(new byte[30720]);
            out.flush();

            byte[] buf = new byte[8192];
            DataInputStream in = new DataInputStream(socket.getInputStream());
            int len = in.read(buf);
            if (len == -1) {
                System.out.println("eof");
                return;
            }
            System.out.println(new String(buf, 0, len));
            Thread.sleep(2000);
        }
    }

    private SSLSocket createSocket() throws Exception {
        SSLContext ctx = JsseSimpleUtil.createSm2SSLContext(
                GmsslTestMaterialPaths.clientPfx(), PWD, GmsslTestMaterialPaths.clientCa());
        SSLSocketFactory factory = ctx.getSocketFactory();
        return (SSLSocket) factory.createSocket(addr, port);
    }
}