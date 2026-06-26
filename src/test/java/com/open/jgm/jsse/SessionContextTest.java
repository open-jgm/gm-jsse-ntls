package com.open.jgm.jsse;

import org.junit.Assert;
import org.junit.Test;

public class SessionContextTest {

    @Test
    public void getIdsReturnsEmptyEnumeration() {
        SessionContext context = new SessionContext();

        Assert.assertNotNull(context.getIds());
        Assert.assertFalse(context.getIds().hasMoreElements());
    }

    @Test
    public void cacheSizeRoundTrip() {
        SessionContext context = new SessionContext();

        context.setSessionCacheSize(8);

        Assert.assertEquals(8, context.getSessionCacheSize());
    }

    @Test
    public void timeoutRoundTrip() {
        SessionContext context = new SessionContext();

        context.setSessionTimeout(60);

        Assert.assertEquals(60, context.getSessionTimeout());
    }

    @Test(expected = IllegalArgumentException.class)
    public void negativeCacheSizeRejected() {
        new SessionContext().setSessionCacheSize(-1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void negativeTimeoutRejected() {
        new SessionContext().setSessionTimeout(-1);
    }
}
