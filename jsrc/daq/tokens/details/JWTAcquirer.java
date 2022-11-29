package daq.tokens.details;

import daq.tokens.AcquireTokenException;
import daq.tokens.internal.JDaqTokens;
import daq.tokens.internal.Mode;


public class JWTAcquirer {
    static {
        try {
            System.loadLibrary("jdaq_tokens");
        }
        catch(final UnsatisfiedLinkError ex) {
            ex.printStackTrace();
            System.exit(-1);
        }
    }

    private JWTAcquirer() {
    }

    public static synchronized String acquire(final Mode mode) throws AcquireTokenException {
        return JDaqTokens.acquire(mode);
    }
}
