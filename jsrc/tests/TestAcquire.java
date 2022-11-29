package tests;

import static org.junit.Assert.*;
import org.junit.Test;

import java.util.Map;

import daq.tokens.AcquireTokenException;
import daq.tokens.JWToken;
import daq.tokens.JWToken.MODE;
import daq.tokens.VerifyTokenException;

public class TestAcquire {

    public TestAcquire() {}

    @Test
    public void checkAquireOnly()
    {
        try {
            String token = JWToken.acquire(MODE.FRESH);
            assertNotNull(token);
        } catch (AcquireTokenException ex) {
            fail();
        }
    }

    @Test
    public void checkAcquireFresh()
    {
        try {
            String token1 = JWToken.acquire(MODE.FRESH);
            String token2 = JWToken.acquire(MODE.FRESH);
            assertNotNull(token1);
            assertNotNull(token2);
            assertNotEquals(token1, token2);
        } catch(AcquireTokenException ex) {
            fail();
        }
    }

    @Test
    public void checkAcquireReuse()
    {
        try {
            String token1 = JWToken.acquire(MODE.REUSE);
            String token2 = JWToken.acquire(MODE.REUSE);
            assertNotNull(token1);
            assertNotNull(token2);
            assertEquals(token1, token2);
        } catch(AcquireTokenException ex) {
            fail();
        }
    }

    @Test
    public void checkAcquireVerify()
    {
        try {
            String token = JWToken.acquire();
            Map<String, Object> result = JWToken.verify(token);
            System.out.println(result.get("sub"));
        } catch(AcquireTokenException ex) {
            fail();
        } catch(VerifyTokenException ex) {
            fail();
        }
    }
}
