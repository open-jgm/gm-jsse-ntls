package com.open.jgm.jsse;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import java.security.Provider;
import java.security.Security;

public class GmSslProvidersTest {

    @Test
    public void ensureInstalledIsIdempotent() {
        GmSslProviders.ensureInstalled();
        int gmProviderCount = countProviders(new GMProvider().getName());
        int bcProviderCount = countProviders(BouncyCastleProvider.PROVIDER_NAME);

        GmSslProviders.ensureInstalled();

        Assert.assertEquals(gmProviderCount, countProviders(new GMProvider().getName()));
        Assert.assertEquals(bcProviderCount, countProviders(BouncyCastleProvider.PROVIDER_NAME));
        Assert.assertNotNull(Security.getProvider(new GMProvider().getName()));
        Assert.assertNotNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME));
    }

    @Test
    public void gmProviderReturnsInstalledProvider() {
        GMProvider provider = GmSslProviders.gmProvider();

        Assert.assertSame(provider, Security.getProvider(provider.getName()));
    }

    private static int countProviders(String name) {
        int count = 0;
        Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; i++) {
            if (name.equals(providers[i].getName())) {
                count++;
            }
        }
        return count;
    }
}
