package com.open.jgm.jsse;

import org.junit.Assert;
import org.junit.Test;

public class KeyScheduleTest {

    @Test
    public void deriveReturnsDefensiveCopies() throws Exception {
        byte[] preMasterSecret = sequence(48, 1);
        byte[] clientRandom = sequence(32, 2);
        byte[] serverRandom = sequence(32, 3);

        KeySchedule.Material material = KeySchedule.derive(preMasterSecret, clientRandom, serverRandom);
        byte[] masterSecret = material.getMasterSecret();
        byte[] clientMacKey = material.getClientMacKey();

        masterSecret[0] = 9;
        clientMacKey[0] = 9;

        Assert.assertFalse(9 == material.getMasterSecret()[0]);
        Assert.assertFalse(9 == material.getClientMacKey()[0]);
    }

    @Test
    public void deriveSlicesExpectedLengths() throws Exception {
        KeySchedule.Material material = KeySchedule.derive(sequence(48, 1), sequence(32, 2), sequence(32, 3));

        Assert.assertEquals(48, material.getMasterSecret().length);
        Assert.assertEquals(32, material.getClientMacKey().length);
        Assert.assertEquals(32, material.getServerMacKey().length);
        Assert.assertEquals(16, material.getClientWriteKey().length);
        Assert.assertEquals(16, material.getServerWriteKey().length);
        Assert.assertEquals(16, material.getClientWriteIV().length);
        Assert.assertEquals(16, material.getServerWriteIV().length);
    }

    private static byte[] sequence(int length, int start) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (start + i);
        }
        return bytes;
    }
}
