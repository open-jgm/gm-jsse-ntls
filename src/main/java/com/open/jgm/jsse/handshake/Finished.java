package com.open.jgm.jsse.handshake;


import com.open.jgm.jsse.Util;
import com.open.jgm.jsse.record.Handshake;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

public class Finished extends Handshake.Body {

    private byte[] verifyData;

    public Finished(byte[] verifyData) {
        this.verifyData = verifyData;
    }

    public static Handshake.Body read(InputStream input, int msgLength) throws IOException {
        return new Finished(Util.safeRead(input, msgLength));
    }

    @Override
    public byte[] getBytes() throws IOException {
        return verifyData;
    }

    @Override
    public String toString() {
        StringWriter str = new StringWriter();
        PrintWriter out = new PrintWriter(str);
        out.println("struct {");
        out.println("  verify_data = " + Util.hexString(verifyData).trim());
        out.println("} Finished;");
        return str.toString();
    }
}
