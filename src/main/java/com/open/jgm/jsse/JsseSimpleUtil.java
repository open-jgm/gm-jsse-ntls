package com.open.jgm.jsse;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * JSSE helpers for SM2/RSA SSLContext and PKCS12 certificate loading.
 */
public final class JsseSimpleUtil {

    private static final Logger LOG = Logger.getLogger(JsseSimpleUtil.class.getName());

    private static BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();
    private static GMProvider GM_PROVIDER = new GMProvider();

    private static String ENC_ALIAS = "Enc";
    private static String SIG_ALIAS = "Sig";
    private static String KEY_STORE_TYPE = "PKCS12";
    private static String GM_ENC_ALIAS = "enc";
    private static String GM_SIG_ALIAS = "sign";
    private static String GM_CA_ALIAS = "ca";
    private static String KEY_MANAGER_FACTORY = "SunX509";
    private static String CERTIFICATE_FACTORY = "X509";
    private static String SSL_CONTEXT = "TLS";

    static {
        Security.addProvider(BC_PROVIDER);
        Security.addProvider(GM_PROVIDER);

    }
    private JsseSimpleUtil() {
    }

    public static SSLContext createSm2SSLContext(String bothP12Path, String pwdStr, String caFile) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE, BC_PROVIDER);
            keyStore.load(null, null);
            keyStore.setKeyEntry(GM_ENC_ALIAS, getP12PrivateKey(ENC_ALIAS, bothP12Path, pwdStr), new char[0],
                    new X509Certificate[]{getP12Certificate(ENC_ALIAS, bothP12Path, pwdStr)});
            keyStore.setKeyEntry(GM_SIG_ALIAS, getP12PrivateKey(SIG_ALIAS, bothP12Path, pwdStr), new char[0],
                    new X509Certificate[]{getP12Certificate(SIG_ALIAS, bothP12Path, pwdStr)});
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KEY_MANAGER_FACTORY);
            keyManagerFactory.init(keyStore, pwdStr.toCharArray());
            X509Certificate caCert = findCaCertificate(caFile);
            keyStore.setCertificateEntry(GM_CA_ALIAS, caCert);
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(CERTIFICATE_FACTORY, GM_PROVIDER);
            trustManagerFactory.init(keyStore);

            SSLContext sslContext = SSLContext.getInstance(SSL_CONTEXT, GM_PROVIDER);
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
            return sslContext;
        } catch (Exception e) {
            LOG.log(Level.WARNING, "createSm2SSLContext failed: bothP12Path={0}, caFile={1}",
                    new Object[]{bothP12Path, caFile});
            LOG.log(Level.WARNING, e.getMessage(), e);
            throw new IllegalArgumentException("create SM2 SSL Socket Factory error.", e);
        }
    }

    public static SSLContext createSm2SSLContext(String sigP12Path, String sigPasswd, String encP12Path,
            String encPasswd, String caFile) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE, BC_PROVIDER);
            keyStore.load(null, null);
            keyStore.setKeyEntry(GM_ENC_ALIAS, getP12PrivateKey(encP12Path, encPasswd), new char[0],
                    new X509Certificate[]{getP12Certificate(encP12Path, encPasswd)});
            keyStore.setKeyEntry(GM_SIG_ALIAS, getP12PrivateKey(sigP12Path, sigPasswd), new char[0],
                    new X509Certificate[]{getP12Certificate(sigP12Path, sigPasswd)});

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KEY_MANAGER_FACTORY);
            keyManagerFactory.init(keyStore, encPasswd.toCharArray());
            X509Certificate caCert = findCaCertificate(caFile);
            keyStore.setCertificateEntry(GM_CA_ALIAS, caCert);
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(CERTIFICATE_FACTORY, GM_PROVIDER);
            trustManagerFactory.init(keyStore);

            SSLContext sslContext = SSLContext.getInstance(SSL_CONTEXT, GM_PROVIDER);
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(),
                    new SecureRandom());
            return sslContext;
        } catch (Exception e) {
            LOG.log(Level.WARNING,
                    "createSm2SSLContext failed: encP12Path={0}, sigP12Path={1}, caFile={2}",
                    new Object[]{encP12Path, sigP12Path, caFile});
            LOG.log(Level.WARNING, e.getMessage(), e);
            throw new IllegalArgumentException("create SM2 SSL Socket Factory error.", e);
        }
    }

    public static SSLContext createRsaSSLContext(String p12Path, String pwdStr, String caFile) {
        try (FileInputStream fileInputStream = new FileInputStream(p12Path);
                FileInputStream caCertFileInputStream = new FileInputStream(caFile)) {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE, BC_PROVIDER);
            keyStore.load(fileInputStream, pwdStr.toCharArray());
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KEY_MANAGER_FACTORY);
            keyManagerFactory.init(keyStore, pwdStr.toCharArray());

            CertificateFactory cf = CertificateFactory.getInstance(CERTIFICATE_FACTORY, BC_PROVIDER);
            X509Certificate caCert = (X509Certificate) cf.generateCertificate(caCertFileInputStream);
            keyStore.setCertificateEntry(GM_CA_ALIAS, caCert);
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(CERTIFICATE_FACTORY);
            trustManagerFactory.init(keyStore);

            SSLContext sslContext;
            try {
                sslContext = SSLContext.getInstance("TLSv1.2");
            } catch (Exception e) {
                sslContext = SSLContext.getInstance(SSL_CONTEXT);
            }
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(),
                    new SecureRandom());
            return sslContext;
        } catch (Exception e) {
            LOG.log(Level.WARNING, "createRsaSSLContext failed: p12Path={0}, caFile={1}",
                    new Object[]{p12Path, caFile});
            LOG.log(Level.WARNING, e.getMessage(), e);
            throw new IllegalArgumentException("create Rsa SSL Socket Factory error.", e);
        }
    }

    public static SSLContext createAuthClientSSLContext(String caFile, boolean isRsa) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE, BC_PROVIDER);
            keyStore.load(null, null);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KEY_MANAGER_FACTORY);
            keyManagerFactory.init(keyStore, null);

            X509Certificate caCert = findCaCertificate(caFile);
            keyStore.setCertificateEntry(GM_CA_ALIAS, caCert);
            if (isRsa) {
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(CERTIFICATE_FACTORY);
                trustManagerFactory.init(keyStore);
                SSLContext sslContext;
                try {
                    sslContext = SSLContext.getInstance("TLSv1.2");
                } catch (Exception e) {
                    sslContext = SSLContext.getInstance(SSL_CONTEXT);
                }
                sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(),
                        new SecureRandom());
                return sslContext;
            }
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(CERTIFICATE_FACTORY, GM_PROVIDER);
            trustManagerFactory.init(keyStore);
            SSLContext sslContext = SSLContext.getInstance(SSL_CONTEXT, GM_PROVIDER);
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
            return sslContext;
        } catch (Exception e) {
            LOG.log(Level.WARNING, "createAuthClientSSLContext failed: caFile={0}", caFile);
            LOG.log(Level.WARNING, e.getMessage(), e);
            throw new IllegalArgumentException("create auth client SSL Socket Factory error.", e);
        }
    }

    public static X509Certificate getP12Certificate(String alias, String p12Path, String pwdStr) {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(KEY_STORE_TYPE, BC_PROVIDER);
        } catch (KeyStoreException e) {
            LOG.log(Level.WARNING, "getP12Certificate: alias={0}, p12Path={1}", new Object[]{alias, p12Path});
            throw new IllegalArgumentException("keyStore bcProvider error.", e);
        }
        try (FileInputStream fis = new FileInputStream(p12Path)) {
            keyStore.load(fis, pwdStr.toCharArray());
            return (X509Certificate) keyStore.getCertificate(alias);
        } catch (Exception e) {
            LOG.log(Level.WARNING, "getP12Certificate: alias={0}, p12Path={1}", new Object[]{alias, p12Path});
            LOG.log(Level.WARNING, e.getMessage(), e);
            throw new IllegalArgumentException("getP12Certificate keyStore load error.", e);
        }
    }

    public static X509Certificate getP12Certificate(String p12Path, String pwdStr) {
        List<String> aliasList = getPfxCertAliasValue(p12Path, pwdStr);
        if (aliasList.isEmpty()) {
            LOG.log(Level.WARNING, "getP12Certificate: p12Path={0}", p12Path);
            throw new IllegalArgumentException("load p12 certificate error.aliasFirst is null");
        }
        return getP12Certificate(aliasList.get(0), p12Path, pwdStr);
    }

    public static PrivateKey getP12PrivateKey(String alias, String p12Path, String pwdStr) {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(KEY_STORE_TYPE, BC_PROVIDER);
        } catch (KeyStoreException e) {
            LOG.log(Level.WARNING, "getP12PrivateKey: alias={0}, p12Path={1}", new Object[]{alias, p12Path});
            LOG.log(Level.WARNING, e.getMessage(), e);
            throw new IllegalArgumentException("keyStore bcProvider error.", e);
        }
        try (FileInputStream fis = new FileInputStream(p12Path)) {
            keyStore.load(fis, pwdStr.toCharArray());
            return (PrivateKey) keyStore.getKey(alias, pwdStr.toCharArray());
        } catch (Exception e) {
            LOG.log(Level.WARNING, "getP12PrivateKey: alias={0}, p12Path={1}", new Object[]{alias, p12Path});
            LOG.log(Level.WARNING, e.getMessage(), e);
            throw new IllegalArgumentException("keyStore get key error.", e);
        }
    }

    public static PrivateKey getP12PrivateKey(String p12Path, String pwdStr) {
        List<String> aliasList = getPfxCertAliasValue(p12Path, pwdStr);
        if (aliasList.isEmpty()) {
            LOG.log(Level.WARNING, "getP12PrivateKey: p12Path={0}", p12Path);
            throw new IllegalArgumentException("load p12 private key error.aliasFirst is null");
        }
        return getP12PrivateKey(aliasList.get(0), p12Path, pwdStr);
    }

    public static List<String> getPfxCertAliasValue(String p12Path, String pwdStr) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE, BC_PROVIDER);
            try (FileInputStream fis = new FileInputStream(p12Path)) {
                keyStore.load(fis, pwdStr.toCharArray());
            }
            Enumeration<String> aliases = keyStore.aliases();
            List<String> list = new ArrayList<>();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    Certificate[] chain = keyStore.getCertificateChain(alias);
                    if (chain != null && chain.length > 0) {
                        list.add(alias);
                    }
                }
            }
            return list;
        } catch (Exception e) {
            LOG.log(Level.WARNING, "getPfxCertAliasValue: p12Path={0}", p12Path);
            LOG.log(Level.WARNING, e.getMessage(), e);
            throw new IllegalArgumentException("getPfxCertAliasValue keyStore load error.", e);
        }
    }

    public static X509Certificate findCaCertificate(String caPath) {
        try (FileInputStream fis = new FileInputStream(caPath)) {
            CertificateFactory cf = CertificateFactory.getInstance(CERTIFICATE_FACTORY, BC_PROVIDER);
            Collection<? extends Certificate> certificates = cf.generateCertificates(fis);
            if (certificates.size() == 1) {
                try (FileInputStream single = new FileInputStream(caPath)) {
                    return (X509Certificate) cf.generateCertificate(single);
                }
            }
            List<X509Certificate> certificateList = getX509CertificateList(certificates);
            X509Certificate rootCertificate = null;
            for (X509Certificate cert : certificateList) {
                if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
                    rootCertificate = cert;
                    break;
                }
            }
            if (rootCertificate == null) {
                throw new IllegalArgumentException("NOT ROOT Certificate");
            }
            List<X509Certificate> excludeRootList = new ArrayList<>();
            for (X509Certificate cert : certificateList) {
                if (!cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
                    excludeRootList.add(cert);
                }
            }
            X509Certificate currentCertificate = rootCertificate;
            while (true) {
                X509Certificate nextCertificate = findRootCertificate(currentCertificate, excludeRootList);
                if (nextCertificate == null) {
                    break;
                }
                currentCertificate = nextCertificate;
            }
            return currentCertificate;
        } catch (Exception e) {
            LOG.log(Level.WARNING, e.getMessage(), e);
            throw new IllegalArgumentException("find Ca Certificate error.", e);
        }
    }

    public static X509Certificate findRootCertificate(String caPath) {
        try (FileInputStream fis = new FileInputStream(caPath)) {
            CertificateFactory cf = CertificateFactory.getInstance(CERTIFICATE_FACTORY, BC_PROVIDER);
            Collection<? extends Certificate> certificates = cf.generateCertificates(fis);
            if (certificates.size() == 1) {
                try (FileInputStream single = new FileInputStream(caPath)) {
                    return (X509Certificate) cf.generateCertificate(single);
                }
            }
            List<X509Certificate> certificateList = getX509CertificateList(certificates);
            for (X509Certificate cert : certificateList) {
                if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
                    return cert;
                }
            }
            throw new IllegalArgumentException("Root Certificate not found.");
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            LOG.log(Level.WARNING, e.getMessage(), e);
            throw new IllegalArgumentException("find Root Certificate error.", e);
        }
    }

    public static X509Certificate findCaCertificate(X509Certificate userCertificate,
            Collection<? extends Certificate> collection) {
        List<X509Certificate> certificates = getX509CertificateList(collection);
        for (X509Certificate cert : certificates) {
            if (cert.getSubjectX500Principal().equals(userCertificate.getIssuerX500Principal())) {
                return cert;
            }
        }
        return null;
    }

    public static X509Certificate findIssuerCertificate(X509Certificate userCertificate,
            List<X509Certificate> certificates) {
        for (X509Certificate cert : certificates) {
            if (cert.getSubjectX500Principal().equals(userCertificate.getIssuerX500Principal())) {
                return cert;
            }
        }
        return null;
    }

    public static X509Certificate findRootCertificate(X509Certificate issuerCert,
            List<X509Certificate> certificates) {
        for (X509Certificate cert : certificates) {
            if (cert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
                return cert;
            }
        }
        return null;
    }

    public static List<X509Certificate> getX509CertificateList(Collection<? extends Certificate> certificates) {
        List<X509Certificate> certificateList = new ArrayList<>();
        for (Certificate certificate : certificates) {
            certificateList.add((X509Certificate) certificate);
        }
        return certificateList;
    }
}