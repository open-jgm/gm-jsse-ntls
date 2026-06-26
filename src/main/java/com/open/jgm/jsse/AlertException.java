package com.open.jgm.jsse;


import com.open.jgm.jsse.record.Alert;

import javax.net.ssl.SSLException;

public class AlertException extends SSLException {
    /**
     *
     */
    private static final long serialVersionUID = -2141851102337515375L;

    private Alert alert;
    private boolean isLocal;

    public AlertException(Alert alert, boolean isLocal) {
        super(alert.getDescription().toString());
        this.alert = alert;
        this.isLocal = isLocal;
    }
}
