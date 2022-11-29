package daq.tokens;

@SuppressWarnings("serial")
public class AcquireTokenException extends ers.Issue {

    /**
     * A DAQ token could not be acquired.
     *
     * @param reason Clear text reason
     * @param cause The cause of this exception
     * 
     */
    public AcquireTokenException(final String reason, final Throwable cause) {
        super(reason, cause);
    }

    /**
     * A DAQ token could not be acquired.
     * 
     * @param reason Clear text reason
     */
    public AcquireTokenException(final String reason) {
        super(reason);
    }
}
