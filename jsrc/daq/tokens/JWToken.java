package daq.tokens;

import java.util.Map;

import daq.tokens.internal.Mode;
import daq.tokens.details.JWTAcquirer;
import daq.tokens.details.JWTCommon;
import daq.tokens.details.JWTVerifier;


/**
 * Utility class to acquire and verify a JSON web token.
 */
public class JWToken {
    /**
     * Enumeration used when a token is acquired.
     */
    public enum MODE {
        /**
         * A new token will be requested
         */
        FRESH(Mode.Fresh),

        /**
         * A previous valid token will be re-used
         */
        REUSE(Mode.Reuse);

        private final Mode orig;

        MODE(final Mode mode) {
            this.orig = mode;
        }

        Mode getOriginal() {
            return this.orig;
        }
    }

    private JWToken() {
    }
    
    /**
     * It acquires a JSON web token
     * 
     * @param mode Whether a new token should be created or a previous valid token should be re-used
     * @return The JSON web token as a string
     * @throws AcquireTokenException The token could not be acquired
     */
    public static String acquire(final MODE mode) throws AcquireTokenException {
        return JWTAcquirer.acquire(mode.getOriginal());
    }

    /**
     * It acquires a new fresh JSON web token
     * 
     * @return The JSON web token as a string
     * @throws AcquireTokenException The token could not be acquired
     */
    public static String acquire() throws AcquireTokenException {
        return JWTAcquirer.acquire(MODE.REUSE.getOriginal());
    }

    /**
     * It verifies a JSON web token
     * 
     * @param token The token to be verified
     * @return A map holding the decoded properties of the token
     * @throws VerifyTokenException The token could not be verified
     */
    public static Map<String, Object> verify(final String token) throws VerifyTokenException {
        return JWTVerifier.verify(token);
    }

    /**
     * It checks whether the JSON token mechanism is enabled for the current process
     * 
     * @return <em>true</em> if the JSON token mechanism is enabled for the current process
     */
    public static boolean enabled() {
        return JWTCommon.enabled();
    }
}
