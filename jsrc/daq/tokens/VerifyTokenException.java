package daq.tokens;

@SuppressWarnings("serial")
public class VerifyTokenException extends ers.Issue {

    /**
     * A DAQ token could not be verified.
     *
     * @param reason Clear text reason
     * @param cause The cause of this exception
     */
    public VerifyTokenException(final String reason, final Throwable cause) {
        super(reason, cause);
    }
}
