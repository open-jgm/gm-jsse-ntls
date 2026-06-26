package com.open.jgm.jsse;

import java.security.cert.X509Certificate;

enum ConnectionEnd {
    server,
    client
}

public class SecurityParameters {
    public byte[] clientRandom;
    public byte[] serverRandom;
    public X509Certificate encryptionCert;
    public byte[] masterSecret;
    ConnectionEnd entity;
    // BulkCipherAlgorithm bulk_cipher_algorithm;
    // CipherType cipher_type;
    byte recordIVLength;

    public byte[] getClientRandom() {
        return copy(clientRandom);
    }

    public void setClientRandom(byte[] clientRandom) {
        this.clientRandom = copy(clientRandom);
    }

    public byte[] getServerRandom() {
        return copy(serverRandom);
    }

    public void setServerRandom(byte[] serverRandom) {
        this.serverRandom = copy(serverRandom);
    }

    public byte[] getMasterSecret() {
        return copy(masterSecret);
    }

    public void setMasterSecret(byte[] masterSecret) {
        this.masterSecret = copy(masterSecret);
    }

    private static byte[] copy(byte[] bytes) {
        return bytes == null ? null : bytes.clone();
    }
}
