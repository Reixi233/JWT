package vn.edu.hcmute.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import vn.edu.hcmute.jwt.security.JwtService;
import vn.edu.hcmute.jwt.user.User;
import java.util.Base64;
import java.util.Date;
import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {
    private final byte[] key = new byte[64];
    private final JwtService service = new JwtService(Base64.getEncoder().encodeToString(key), 3600000, "test");

    @Test
    void generatesVerifiableHs256Token() throws Exception {
        String token = service.generateToken(new User("Demo", "demo@example.com", "not-in-token"));
        assertEquals("demo@example.com", service.extractUsername(token));
        SignedJWT parsed = SignedJWT.parse(token);
        assertEquals(JWSAlgorithm.HS256, parsed.getHeader().getAlgorithm());
        assertEquals(3600000, parsed.getJWTClaimsSet().getExpirationTime().getTime()
                - parsed.getJWTClaimsSet().getIssueTime().getTime());
        assertFalse(parsed.getPayload().toString().contains("not-in-token"));
    }

    private String token(String issuer, Date expiry, JWSAlgorithm algorithm, byte[] signingKey) throws Exception {
        var claims = new JWTClaimsSet.Builder().subject("demo@example.com").issuer(issuer)
                .issueTime(new Date(System.currentTimeMillis() - 10000)).expirationTime(expiry).build();
        var jwt = new SignedJWT(new JWSHeader.Builder(algorithm).type(JOSEObjectType.JWT).build(), claims);
        jwt.sign(new MACSigner(signingKey));
        return jwt.serialize();
    }

    @Test void rejectsExpiredToken() throws Exception {
        String token = token("test", new Date(System.currentTimeMillis() - 1000), JWSAlgorithm.HS256, key);
        assertThrows(BadCredentialsException.class, () -> service.extractUsername(token));
    }
    @Test void rejectsMissingExpiration() throws Exception {
        String token = token("test", null, JWSAlgorithm.HS256, key);
        assertThrows(BadCredentialsException.class, () -> service.extractUsername(token));
    }
    @Test void rejectsWrongIssuer() throws Exception {
        String token = token("other", new Date(System.currentTimeMillis() + 60000), JWSAlgorithm.HS256, key);
        assertThrows(BadCredentialsException.class, () -> service.extractUsername(token));
    }
    @Test void rejectsWrongAlgorithm() throws Exception {
        String token = token("test", new Date(System.currentTimeMillis() + 60000), JWSAlgorithm.HS512, key);
        assertThrows(BadCredentialsException.class, () -> service.extractUsername(token));
    }
    @Test void rejectsWrongSignature() throws Exception {
        byte[] otherKey = key.clone();
        otherKey[0] = 1;
        String token = token("test", new Date(System.currentTimeMillis() + 60000), JWSAlgorithm.HS256, otherKey);
        assertThrows(BadCredentialsException.class, () -> service.extractUsername(token));
    }
    @Test void rejectsMalformedToken() {
        assertThrows(BadCredentialsException.class, () -> service.extractUsername("invalid"));
    }
    @Test void rejectsWeakKey() {
        assertThrows(IllegalArgumentException.class, () -> new JwtService("YWJj", 1000, "test"));
    }
}