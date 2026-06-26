package com.open.jgm.jsse;

import org.junit.Assert;
import org.junit.Test;

import javax.net.ssl.SSLPeerUnverifiedException;
import java.util.Collections;

public class GMSSLSessionTest {

    @Test
    public void newSessionIsValidWithTimestamps() {
        GMSSLSession session = new GMSSLSession(
                Collections.singletonList(CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3),
                Collections.singletonList(ProtocolVersion.NTLS_1_1));
        Assert.assertTrue(session.isValid());
        Assert.assertTrue(session.getCreationTime() > 0);
        Assert.assertTrue(session.getLastAccessedTime() >= session.getCreationTime());
    }

    @Test
    public void invalidateMarksSessionInvalid() {
        GMSSLSession session = new GMSSLSession();
        session.invalidate();
        Assert.assertFalse(session.isValid());
    }

    @Test
    public void peerCertificatesRequireVerification() throws Exception {
        GMSSLSession session = new GMSSLSession();
        session.peerVerified = false;
        try {
            session.getPeerCertificates();
            Assert.fail();
        } catch (SSLPeerUnverifiedException expected) {
            // ok
        }
    }

    @Test
    public void sessionValueBagRoundTrip() {
        GMSSLSession session = new GMSSLSession();
        session.putValue("k", "v");
        Assert.assertEquals("v", session.getValue("k"));
        Assert.assertEquals(1, session.getValueNames().length);
        session.removeValue("k");
        Assert.assertNull(session.getValue("k"));
    }

    @Test
    public void sessionIdClonesBytes() {
        byte[] id = new byte[]{1, 2, 3};
        GMSSLSession.ID sid = new GMSSLSession.ID(id);
        id[0] = 9;
        Assert.assertEquals(1, sid.getId()[0]);
    }
}