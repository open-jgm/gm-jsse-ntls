package com.open.jgm.jsse;

import javax.net.ssl.X509TrustManager;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class GMX509TrustManager implements X509TrustManager {
    private final X509Certificate[] trusted;

    GMX509TrustManager(X509Certificate[] trusted) {
        this.trusted = trusted == null ? null : (X509Certificate[]) trusted.clone();
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        if (trusted == null) {
            return new X509Certificate[0];
        }
        return (X509Certificate[]) trusted.clone();
    }

    private void checkTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("empty certificate chain");
        }
        if (trusted == null || trusted.length == 0) {
            throw new CertificateException("no trust anchors");
        }

        for (int i = 0; i < chain.length; i++) {
            if (chain[i] == null) {
                throw new CertificateException("certificate chain contains null entry");
            }
            chain[i].checkValidity();
        }

        for (int i = 0; i < chain.length; i++) {
            if (i + 1 < chain.length && isIssuedBy(chain[i], chain[i + 1])) {
                verifyCertificate(chain[i], chain[i + 1]);
            } else {
                verifyTrustAnchor(chain[i]);
            }
        }
    }

    private void verifyTrustAnchor(X509Certificate certificate) throws CertificateException {
        CertificateException lastFailure = null;
        for (int i = 0; i < trusted.length; i++) {
            X509Certificate trustAnchor = trusted[i];
            if (trustAnchor == null) {
                continue;
            }
            try {
                trustAnchor.checkValidity();
                verifyCertificate(certificate, trustAnchor);
                return;
            } catch (CertificateException e) {
                lastFailure = e;
            }
        }

        CertificateException failure = new CertificateException("certificate chain is not trusted");
        if (lastFailure != null) {
            failure.initCause(lastFailure);
        }
        throw failure;
    }

    private static boolean isIssuedBy(X509Certificate certificate, X509Certificate issuer) {
        return certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal());
    }

    private static void verifyCertificate(X509Certificate certificate, X509Certificate issuer)
            throws CertificateException {
        try {
            certificate.verify(issuer.getPublicKey());
        } catch (GeneralSecurityException e) {
            throw new CertificateException("certificate signature verification failed", e);
        }
    }
}
