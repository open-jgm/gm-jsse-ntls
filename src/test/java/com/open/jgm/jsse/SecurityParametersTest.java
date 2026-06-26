package com.open.jgm.jsse;

import org.junit.Assert;
import org.junit.Test;

public class SecurityParametersTest {

    @Test
    public void clientRandomIsDefensivelyCopied() {
        SecurityParameters parameters = new SecurityParameters();
        byte[] random = new byte[]{1, 2, 3};

        parameters.setClientRandom(random);
        random[0] = 9;
        byte[] copy = parameters.getClientRandom();
        copy[1] = 8;

        Assert.assertArrayEquals(new byte[]{1, 2, 3}, parameters.getClientRandom());
    }

    @Test
    public void serverRandomIsDefensivelyCopied() {
        SecurityParameters parameters = new SecurityParameters();
        byte[] random = new byte[]{4, 5, 6};

        parameters.setServerRandom(random);
        random[0] = 9;
        byte[] copy = parameters.getServerRandom();
        copy[1] = 8;

        Assert.assertArrayEquals(new byte[]{4, 5, 6}, parameters.getServerRandom());
    }

    @Test
    public void masterSecretIsDefensivelyCopied() {
        SecurityParameters parameters = new SecurityParameters();
        byte[] secret = new byte[]{7, 8, 9};

        parameters.setMasterSecret(secret);
        secret[0] = 1;
        byte[] copy = parameters.getMasterSecret();
        copy[1] = 2;

        Assert.assertArrayEquals(new byte[]{7, 8, 9}, parameters.getMasterSecret());
    }
}
