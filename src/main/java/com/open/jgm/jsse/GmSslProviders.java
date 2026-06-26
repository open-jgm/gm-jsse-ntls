package com.open.jgm.jsse;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

public final class GmSslProviders {
    private static final String BOUNCY_CASTLE_PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
    private static final GMProvider GM_PROVIDER = new GMProvider();

    private GmSslProviders() {
    }

    public static synchronized void ensureInstalled() {
        if (Security.getProvider(BOUNCY_CASTLE_PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(GM_PROVIDER.getName()) == null) {
            Security.addProvider(GM_PROVIDER);
        }
    }

    public static synchronized GMProvider gmProvider() {
        ensureInstalled();
        Provider provider = Security.getProvider(GM_PROVIDER.getName());
        if (provider instanceof GMProvider) {
            return (GMProvider) provider;
        }
        return GM_PROVIDER;
    }
}
