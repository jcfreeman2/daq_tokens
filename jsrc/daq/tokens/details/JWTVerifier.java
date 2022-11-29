package daq.tokens.details;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.net.URL;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import daq.tokens.VerifyTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolverAdapter;


public class JWTVerifier {
    private final static String AUDIENCE = "atlas-tdaq-token";
    private final static String ISSUER = "https://auth.cern.ch/auth/realms/cern";
    private final static KeyResolver RESOLVER = new KeyResolver();
    private final static HashMap<String, Claims> CACHE = new HashMap<String, Claims>(); // Cache of recent tokens

    private static class VerifyTokenError extends RuntimeException {
        private static final long serialVersionUID = -3987478280231296699L;

        VerifyTokenError(final String message, final Throwable cause) {
            super(message, cause);
        }
    }

    private static class KeyResolver extends SigningKeyResolverAdapter {
        private final static String TDAQ_TOKEN_PUBLIC_KEY_URL_ENV = "TDAQ_TOKEN_PUBLIC_KEY_URL";
        private final static String CERN_PUBLIC_KEYS_URL = "https://auth.cern.ch/auth/realms/cern/protocol/openid-connect/certs";
        private final static String PUBLIC_KEYS_URL = KeyResolver.getPubKeysURL();

        // Known keys
        private final HashMap<String, RSAPublicKey> keys = new HashMap<String, RSAPublicKey>();

        private static String getPubKeysURL() {
            final String public_keys_url = System.getenv(KeyResolver.TDAQ_TOKEN_PUBLIC_KEY_URL_ENV);
            if(public_keys_url != null) {
                return public_keys_url;
            }

            return KeyResolver.CERN_PUBLIC_KEYS_URL;
        }

        @Override
        public Key resolveSigningKey(@SuppressWarnings("rawtypes") final JwsHeader jwsHeader, final Claims claims) throws VerifyTokenError {
            final String keyId = jwsHeader.getKeyId();

            RSAPublicKey result = this.keys.get(keyId);
            if(result == null) {
                final String[] urls = KeyResolver.PUBLIC_KEYS_URL.split("\\|");
                for(final String url : urls) {
                    try (final BufferedInputStream stream = new BufferedInputStream(new URL(url).openStream())) {
                        final StringBuilder builder = new StringBuilder();

                        int c;
                        while((c = stream.read()) != -1) {
                            builder.append((char) c);
                        }

                        final String keyData = builder.toString();
                        if(keyData.startsWith("-----BEGIN")) {
                            // assume PEM encoded RSA key
                            final X509EncodedKeySpec keySpec =
                                                             new X509EncodedKeySpec(Base64.getDecoder().decode(keyData.replace("-----BEGIN PUBLIC KEY-----", "")
                                                                                                                      .replace("-----END PUBLIC KEY-----", "")
                                                                                                                      .replace(System.lineSeparator(), "")));
                            final RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);

                            { // original MD5 based key id
                                final byte[] digest = MessageDigest.getInstance("MD5").digest(key.getEncoded());

                                final StringBuilder pem_kid = new StringBuilder();
                                for(final byte aByte : digest) {
                                    pem_kid.append(String.format("%02x", Byte.valueOf(aByte)));
                                }

                                this.keys.put(pem_kid.toString(), key);
                           }

                           { // SHA256 based key id
                                final byte[] digest = MessageDigest.getInstance("SHA-256").digest(key.getEncoded());

                                final StringBuilder pem_kid = new StringBuilder();
                                for(final byte aByte : digest) {
                                    pem_kid.append(String.format("%02x", Byte.valueOf(aByte)));
                                }

                                this.keys.put(pem_kid.toString(), key);
                           }

                        } else {
                            final JsonObject jwks = new JsonParser().parse(keyData).getAsJsonObject();
                            final JsonObject jwk = jwks.getAsJsonArray("keys").get(0).getAsJsonObject();
                            final String jwk_kid = jwk.get("kid").getAsString();
                            final String jwk_x5c = jwk.get("x5c").getAsString();

                            final CertificateFactory factory = CertificateFactory.getInstance("X.509");
                            final X509Certificate cert =
                                                       (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(jwk_x5c)));

                            final RSAPublicKey key = (RSAPublicKey) cert.getPublicKey();
                            this.keys.put(jwk_kid, key);
                        }
                    }
                    catch(final java.io.IOException ex) {
                        throw new VerifyTokenError("Cannot read public key: " + ex, ex);
                    }
                    catch(final java.security.NoSuchAlgorithmException ex) {
                        throw new VerifyTokenError("RSA and/or MD5 algorithms may not be available for the current platform: " + ex, ex);
                    }
                    catch(final java.security.spec.InvalidKeySpecException ex) {
                        throw new VerifyTokenError("Invalid key: " + ex, ex);
                    }
                    catch(final java.security.cert.CertificateException ex) {
                        throw new VerifyTokenError("Wrong certificate: " + ex, ex);
                    }
                }

                result = this.keys.get(keyId);
            }

            return result;
        }
    }

    private JWTVerifier() {
    }

    public static synchronized Map<String, Object> verify(final String token) throws VerifyTokenException {
        final long now = new Date().getTime() * 1000;

        // We are already on the slow path, so let's check the cache for expired entries.
        JWTVerifier.CACHE.entrySet().removeIf(entry -> {
            return entry.getValue().get("exp", Long.class).longValue() < now;
        });

        Claims result = null;

        // Expired entries are no more in the cache
        try {
            result = JWTVerifier.CACHE.computeIfAbsent(token, key -> {
                return Jwts.parserBuilder().setSigningKeyResolver(JWTVerifier.RESOLVER)
                                           .requireAudience(JWTVerifier.AUDIENCE)
                                           .requireIssuer(JWTVerifier.ISSUER)
                                           .build()
                                           .parseClaimsJws(token)
                                           .getBody();
            });
        }
        catch(final VerifyTokenError ex) {
            throw new VerifyTokenException(ex.getMessage(), ex);
        }
        catch(final IllegalArgumentException | JwtException ex) {
            throw new VerifyTokenException("Unexpected exception: " + ex, ex);
        }

        return result;
    }
}
