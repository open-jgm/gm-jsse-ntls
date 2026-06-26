package com.open.jgm.jsse.handshake;

import com.open.jgm.jsse.CipherSuite;
import com.open.jgm.jsse.CompressionMethod;
import com.open.jgm.jsse.ProtocolVersion;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class ServerHelloTest {

    @Test
    public void toStringTest() {
        byte[] bytes = new byte[]{10};
        CompressionMethod compression = Mockito.mock(CompressionMethod.class);
        Mockito.when(compression.toString()).thenReturn("compression");
        ServerHello serverHello = new ServerHello(ProtocolVersion.NTLS_1_1, bytes, bytes,
                CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3, compression);
        String str = serverHello.toString();
        Assert.assertTrue(str.contains("version = NTLSv1.1;"));
        Assert.assertTrue(str.contains("random = 0a"));
        Assert.assertTrue(str.contains("sessionId = 0a"));
        Assert.assertTrue(str.contains("cipherSuite = ECC-SM2-WITH-SM4-CBC-SM3;"));
        Assert.assertTrue(str.contains("compressionMethod = compression;"));
    }

    @Test
    public void getTest() throws Exception{
        byte[] bytes = new byte[]{10};
        CompressionMethod compression = Mockito.mock(CompressionMethod.class);
        ServerHello serverHello = new ServerHello(ProtocolVersion.NTLS_1_1, bytes, bytes,
                CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3, compression);
        Assert.assertEquals(compression, serverHello.getCompressionMethod());
        Assert.assertNotNull(serverHello.getBytes());
        Assert.assertEquals(10, serverHello.getSessionId()[0]);
        Assert.assertEquals(bytes, serverHello.getRandom());
        Assert.assertEquals(CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3, serverHello.getCipherSuite());
    }
}
