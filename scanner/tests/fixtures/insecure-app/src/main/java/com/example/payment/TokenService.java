package com.example.payment;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

/**
 * JWT signing with a hardcoded HMAC secret, plus a BouncyCastle provider.
 * Fixture for ECDAT integration tests.
 */
public class TokenService {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // Hardcoded HS256 secret - the classic JWT failure
    private static final String JWT_SECRET = "changeme-in-production-please-32b";

    private final SecretKey key = Keys.hmacShaKeyFor(JWT_SECRET.getBytes());

    public String issueToken(String subject) {
        return Jwts.builder()
            .setSubject(subject)
            .setIssuedAt(new Date())
            .signWith(key, SignatureAlgorithm.HS256)
            .compact();
    }

    public String issueRs256Token(String subject, java.security.PrivateKey pk) {
        return Jwts.builder()
            .setSubject(subject)
            .signWith(pk, SignatureAlgorithm.RS256)
            .compact();
    }

    public void parse(String token) {
        Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
    }
}
