package daq.tokens.details;

import daq.tokens.internal.JDaqTokens;


public class JWTCommon {
    static {
        try {
            System.loadLibrary("jdaq_tokens");
        }
        catch(final UnsatisfiedLinkError ex) {
            ex.printStackTrace();
            System.exit(-1);
        }
    }

    private JWTCommon() {
    }

    public static boolean enabled() {
        return JDaqTokens.enabled();
    }
}
