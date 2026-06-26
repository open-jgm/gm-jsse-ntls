package com.open.jgm.jsse;

import com.open.jgm.jsse.record.Alert;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class RecordStreamSecurityTest {

    private static final byte[] KEY = new byte[16];
    private static final byte[] IV = new byte[16];
    private static final byte[] MAC_KEY = new byte[32];

    static {
        Arrays.fill(KEY, (byte) 0x01);
        Arrays.fill(IV, (byte) 0x02);
        Arrays.fill(MAC_KEY, (byte) 0x03);
    }

    @Test
    public void roundTripEncryptDecrypt() throws Exception {
        RecordStream writer = newStream();
        RecordStream reader = newStream();
        configureCrypto(writer, reader);

        byte[] plain = "hello-gmssl".getBytes(StandardCharsets.UTF_8);
        Record in = new Record(Record.ContentType.APPLICATION_DATA, ProtocolVersion.NTLS_1_1, plain);
        Record encrypted = writer.encrypt(in);
        byte[] out = reader.decrypt(encrypted);
        Assert.assertArrayEquals(plain, out);
    }

    @Test
    public void invalidCiphertextLengthNotBlockAligned() throws Exception {
        RecordStream reader = newStream();
        configureCrypto(null, reader);
        Record bad = new Record(Record.ContentType.APPLICATION_DATA, ProtocolVersion.NTLS_1_1,
                new byte[17]);
        try {
            reader.decrypt(bad);
            Assert.fail();
        } catch (AlertException e) {
            Assert.assertEquals(Alert.Description.BAD_RECORD_MAC.toString(), e.getMessage());
        }
    }

    @Test
    public void tamperedMacFailsWithBadRecordMac() throws Exception {
        RecordStream writer = newStream();
        RecordStream reader = newStream();
        configureCrypto(writer, reader);

        Record encrypted = writer.encrypt(new Record(Record.ContentType.APPLICATION_DATA,
                ProtocolVersion.NTLS_1_1, "x".getBytes(StandardCharsets.UTF_8)));
        encrypted.fragment[encrypted.fragment.length - 2] ^= 0x55;
        try {
            reader.decrypt(encrypted);
            Assert.fail();
        } catch (AlertException e) {
            Assert.assertEquals(Alert.Description.BAD_RECORD_MAC.toString(), e.getMessage());
        }
    }

    @Test
    public void invalidPaddingLengthByteFails() throws Exception {
        RecordStream writer = newStream();
        RecordStream reader = newStream();
        configureCrypto(writer, reader);

        Record encrypted = writer.encrypt(new Record(Record.ContentType.APPLICATION_DATA,
                ProtocolVersion.NTLS_1_1, "pad".getBytes(StandardCharsets.UTF_8)));
        encrypted.fragment[encrypted.fragment.length - 1] = 0;
        try {
            reader.decrypt(encrypted);
            Assert.fail();
        } catch (AlertException e) {
            Assert.assertEquals(Alert.Description.BAD_RECORD_MAC.toString(), e.getMessage());
        }
    }

    @Test
    public void inconsistentPaddingBytesFail() throws Exception {
        RecordStream writer = newStream();
        RecordStream reader = newStream();
        configureCrypto(writer, reader);

        Record encrypted = writer.encrypt(new Record(Record.ContentType.APPLICATION_DATA,
                ProtocolVersion.NTLS_1_1, "pad2".getBytes(StandardCharsets.UTF_8)));
        int padLen = encrypted.fragment[encrypted.fragment.length - 1] & 0xFF;
        if (padLen > 1) {
            encrypted.fragment[encrypted.fragment.length - 2] = (byte) (padLen - 1);
        }
        try {
            reader.decrypt(encrypted);
            Assert.fail();
        } catch (AlertException e) {
            Assert.assertEquals(Alert.Description.BAD_RECORD_MAC.toString(), e.getMessage());
        }
    }

    private static RecordStream newStream() {
        return new RecordStream(new ByteArrayInputStream(new byte[0]), new ByteArrayOutputStream());
    }

    private static void configureCrypto(RecordStream writer, RecordStream reader) {
        if (writer != null) {
            SM4Engine writeEngine = new SM4Engine();
            writeEngine.init(true, new KeyParameter(KEY));
            writer.setWriteCipher(writeEngine);
            writer.setEncryptIV(IV.clone());
            writer.setEncryptMacKey(MAC_KEY.clone());
        }
        if (reader != null) {
            SM4Engine readEngine = new SM4Engine();
            readEngine.init(false, new KeyParameter(KEY));
            reader.setReadCipher(readEngine);
            reader.setDecryptIV(IV.clone());
            reader.setDecryptMacKey(MAC_KEY.clone());
        }
    }
}