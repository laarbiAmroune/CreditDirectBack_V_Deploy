// JwtUtil.java

package creditdirect.clientmicrocervice.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import creditdirect.clientmicrocervice.entities.RoleType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration.ms}")
    private long expirationTimeMs;

    public String generateToken(Long userId, RoleType role) {
        try {
            Instant now = Instant.now();
            Date issuedAt = Date.from(now);
            Date expiresAt = Date.from(now.plusMillis(expirationTimeMs));

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(Long.toString(userId))
                    .claim("role", role.toString())
                    .issueTime(issuedAt)
                    .expirationTime(expiresAt)
                    .build();

            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

            MACSigner signer = new MACSigner(secretKey);
            signedJWT.sign(signer);

            return signedJWT.serialize();
        } catch (JOSEException e) {
            // Handle exception
            throw new RuntimeException("Failed to generate JWT token", e);
        }
    }

    public Long extractUserId(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            return Long.parseLong(claimsSet.getSubject());
        } catch (ParseException | NumberFormatException e) {
            // Handle specific exceptions
            return null;
        }
    }

    public String extractRole(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            return claimsSet.getStringClaim("role");
        } catch (ParseException e) {
            // Handle exception
            return null;
        }
    }

    public boolean validateToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            MACVerifier verifier = new MACVerifier(secretKey);
            return signedJWT.verify(verifier);
        } catch (ParseException | JOSEException e) {
            return false;
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            Date expirationTime = claimsSet.getExpirationTime();
            return expirationTime != null && expirationTime.before(new Date());
        } catch (ParseException e) {
            // Handle exception
            return false;
        }
    }

    public Collection<? extends GrantedAuthority> extractAuthorities(String token) {
        String role = extractRole(token);
        if (role != null) {
            return Collections.singleton(new SimpleGrantedAuthority(role));
        }
        return Collections.emptyList();
    }
}
