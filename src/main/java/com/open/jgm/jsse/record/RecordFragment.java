package com.open.jgm.jsse.record;

import java.io.IOException;

public interface RecordFragment {
    public byte[] getBytes() throws IOException;
}
