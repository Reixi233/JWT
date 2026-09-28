package vn.edu.hcmute.jwt.security;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {
    private final byte[] secret;
    private final long expirationTime;
    private final String issuer;

    public JwtService(@Value("${security.jwt.secret-key}") String base64Secret,
                      @Value("${security.jwt.expiration-time}") long expirationTime,
                      @Value("${security.jwt.issuer}") String issuer) {
        this.secret = Base64.getDecoder().decode(base64Secret);
        if (secret.length < 32) {
            throw new IllegalArgumentException("JWT_SECRET must contain at least 32 random bytes, Base64 encoded");
        }
        if (expirationTime <= 0) {
            throw new IllegalArgumentException("JWT expiration must be positive");
        }
        this.expirationTime = expirationTime;
        this.issuer = issuer;
    }

    public String generateToken(UserDetails user) {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(user.getUsername()).issuer(issuer)
                .issueTime(Date.from(now)).expirationTime(Date.from(now.plusMillis(expirationTime)))
                .jwtID(UUID.randomUUID().toString()).build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT).build(), claims);
        try {
            jwt.sign(new MACSigner(secret));
            return jwt.serialize();
        } catch (JOSEException exception) {
            throw new IllegalStateException("Cannot sign JWT", exception);
        }
    }

    // Never trust the subject until BOTH signature and claims have been verified.
    public String extractUsername(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (!JWSAlgorithm.HS256.equals(jwt.getHeader().getAlgorithm())
                    || !JOSEObjectType.JWT.equals(jwt.getHeader().getType())
                    || !jwt.verify(new MACVerifier(secret))) {
                throw new BadCredentialsException("Invalid JWT");
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Date now = new Date();
            if (!issuer.equals(claims.getIssuer())
                    || claims.getSubject() == null || claims.getSubject().isBlank()
                    || claims.getExpirationTime() == null || !claims.getExpirationTime().after(now)
                    || claims.getIssueTime() == null || claims.getIssueTime().after(now)
                    || (claims.getNotBeforeTime() != null && claims.getNotBeforeTime().after(now))) {
                throw new BadCredentialsException("Invalid or expired JWT");
            }
            return claims.getSubject();
        } catch (ParseException | JOSEException | IllegalArgumentException exception) {
            throw new BadCredentialsException("Invalid JWT", exception);
        }
    }

    public long getExpirationTime() { return expirationTime; }
}