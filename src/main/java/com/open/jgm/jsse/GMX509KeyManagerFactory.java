package com.open.jgm.jsse;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import java.security.*;

public class GMX509KeyManagerFactory extends KeyManagerFactorySpi {

    @Override
    protected KeyManager[] engineGetKeyManagers() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    protected void engineInit(ManagerFactoryParameters arg0) throws InvalidAlgorithmParameterException {
        // TODO Auto-generated method stub

    }

    @Override
    protected void engineInit(KeyStore arg0, char[] arg1)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        // TODO Auto-generated method stub

    }

}
