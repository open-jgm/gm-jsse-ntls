package com.open.jgm.jsse;

import com.open.jgm.jsse.crypto.Crypto;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.net.ssl.SSLException;
import java.io.ByteArrayOutputStream;

public final class KeySchedule {
    private static final byte[] MASTER_SECRET_LABEL = "master secret".getBytes();
    private static final byte[] KEY_EXPANSION_LABEL = "key expansion".getBytes();
    private static final int MAC_KEY_LENGTH = 32;
    private static final int WRITE_KEY_LENGTH = 16;
    private static final int WRITE_IV_LENGTH = 16;
    private static final int KEY_BLOCK_LENGTH = 128;

    private KeySchedule() {
    }

    public static Material derive(byte[] preMasterSecret, byte[] clientRandom, byte[] serverRandom)
            throws SSLException {
        try {
            ByteArrayOutputStream masterSeed = new ByteArrayOutputStream();
            masterSeed.write(clientRandom);
            masterSeed.write(serverRandom);
            byte[] masterSecret = Crypto.prf(preMasterSecret, MASTER_SECRET_LABEL,
                    masterSeed.toByteArray(), preMasterSecret.length);

            ByteArrayOutputStream keyBlockSeed = new ByteArrayOutputStream();
            keyBlockSeed.write(serverRandom);
            keyBlockSeed.write(clientRandom);
            byte[] keyBlock = Crypto.prf(masterSecret, KEY_EXPANSION_LABEL,
                    keyBlockSeed.toByteArray(), KEY_BLOCK_LENGTH);

            return new Material(masterSecret,
                    slice(keyBlock, 0, MAC_KEY_LENGTH),
                    slice(keyBlock, 32, MAC_KEY_LENGTH),
                    slice(keyBlock, 64, WRITE_KEY_LENGTH),
                    slice(keyBlock, 80, WRITE_KEY_LENGTH),
                    slice(keyBlock, 96, WRITE_IV_LENGTH),
                    slice(keyBlock, 112, WRITE_IV_LENGTH));
        } catch (Exception ex) {
            throw new SSLException("caculate key block failed", ex);
        }
    }

    public static void applyClientWrite(RecordStream recordStream, Material material) {
        recordStream.setEncryptMacKey(material.getClientMacKey());
        recordStream.setDecryptMacKey(material.getServerMacKey());
        recordStream.setWriteCipher(cipher(true, material.getClientWriteKey()));
        recordStream.setReadCipher(cipher(false, material.getServerWriteKey()));
        recordStream.setEncryptIV(material.getClientWriteIV());
        recordStream.setDecryptIV(material.getServerWriteIV());
    }

    public static void applyServerWrite(RecordStream recordStream, Material material) {
        recordStream.setDecryptMacKey(material.getClientMacKey());
        recordStream.setEncryptMacKey(material.getServerMacKey());
        recordStream.setReadCipher(cipher(false, material.getClientWriteKey()));
        recordStream.setWriteCipher(cipher(true, material.getServerWriteKey()));
        recordStream.setDecryptIV(material.getClientWriteIV());
        recordStream.setEncryptIV(material.getServerWriteIV());
    }

    private static SM4Engine cipher(boolean forEncryption, byte[] key) {
        SM4Engine cipher = new SM4Engine();
        cipher.init(forEncryption, new KeyParameter(key));
        return cipher;
    }

    private static byte[] slice(byte[] source, int offset, int length) {
        byte[] result = new byte[length];
        System.arraycopy(source, offset, result, 0, length);
        return result;
    }

    public static final class Material {
        private final byte[] masterSecret;
        private final byte[] clientMacKey;
        private final byte[] serverMacKey;
        private final byte[] clientWriteKey;
        private final byte[] serverWriteKey;
        private final byte[] clientWriteIV;
        private final byte[] serverWriteIV;

        private Material(byte[] masterSecret, byte[] clientMacKey, byte[] serverMacKey,
                byte[] clientWriteKey, byte[] serverWriteKey, byte[] clientWriteIV,
                byte[] serverWriteIV) {
            this.masterSecret = copy(masterSecret);
            this.clientMacKey = copy(clientMacKey);
            this.serverMacKey = copy(serverMacKey);
            this.clientWriteKey = copy(clientWriteKey);
            this.serverWriteKey = copy(serverWriteKey);
            this.clientWriteIV = copy(clientWriteIV);
            this.serverWriteIV = copy(serverWriteIV);
        }

        public byte[] getMasterSecret() {
            return copy(masterSecret);
        }

        public byte[] getClientMacKey() {
            return copy(clientMacKey);
        }

        public byte[] getServerMacKey() {
            return copy(serverMacKey);
        }

        public byte[] getClientWriteKey() {
            return copy(clientWriteKey);
        }

        public byte[] getServerWriteKey() {
            return copy(serverWriteKey);
        }

        public byte[] getClientWriteIV() {
            return copy(clientWriteIV);
        }

        public byte[] getServerWriteIV() {
            return copy(serverWriteIV);
        }

        private static byte[] copy(byte[] bytes) {
            return bytes == null ? null : bytes.clone();
        }
    }
}
