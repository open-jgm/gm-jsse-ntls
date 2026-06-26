package com.open.jgm.jsse.handshake;



import com.open.jgm.jsse.record.Handshake;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

public class ServerHelloDone extends Handshake.Body {

    public static Handshake.Body read(InputStream input) {
        return new ServerHelloDone();
    }

    @Override
    public byte[] getBytes() throws IOException {
        return new byte[0];
    }

    @Override
    public String toString() {
        StringWriter str = new StringWriter();
        PrintWriter out = new PrintWriter(str);
        out.println("struct {");
        out.println("} ServerHelloDone;");
        return str.toString();
    }

}
