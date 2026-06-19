package com.security.system.security;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.security.system.model.Permission;
import com.security.system.model.Role;
import com.security.system.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class TokenProvider {

    private static final Logger log = LoggerFactory.getLogger(TokenProvider.class);

    private final RsaKeyManager rsaKeyManager;

    @Value("${app.jwt.expiration:900}")
    private long jwtExpirationInSeconds;

    public TokenProvider(RsaKeyManager rsaKeyManager) {
        this.rsaKeyManager = rsaKeyManager;
    }

    public String generateAccessToken(User user) {
        try {
            RSASSASigner signer = new RSASSASigner(rsaKeyManager.getPrivateKey());

            List<String> roles = user.getRoles().stream()
                    .map(Role::getRoleName)
                    .collect(Collectors.toList());

            List<String> permissions = user.getRoles().stream()
                    .flatMap(role -> role.getPermissions().stream())
                    .map(Permission::getPermissionName)
                    .distinct()
                    .collect(Collectors.toList());

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(user.getUsername())
                    .issueTime(new Date())
                    .expirationTime(new Date(System.currentTimeMillis() + jwtExpirationInSeconds * 1000))
                    .claim("tenant_id", user.getTenantId())
                    .claim("roles", roles)
                    .claim("permissions", permissions)
                    .build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(rsaKeyManager.getKeyId())
                    .type(JOSEObjectType.JWT)
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            signedJWT.sign(signer);

            return signedJWT.serialize();
        } catch (Exception e) {
            log.error("Error generating JWT access token", e);
            throw new RuntimeException("Could not generate JWT access token", e);
        }
    }

    public boolean validateToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            RSASSAVerifier verifier = new RSASSAVerifier(rsaKeyManager.getRsaKey().toRSAPublicKey());

            if (!signedJWT.verify(verifier)) {
                log.warn("Invalid JWT signature");
                return false;
            }

            Date expirationTime = signedJWT.getJWTClaimsSet().getExpirationTime();
            if (expirationTime == null || expirationTime.before(new Date())) {
                log.warn("JWT token has expired");
                return false;
            }

            return true;
        } catch (Exception e) {
            log.error("JWT validation failed", e);
            return false;
        }
    }

    public String getUsernameFromToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet().getSubject();
        } catch (Exception e) {
            log.error("Failed to extract username from token", e);
            throw new IllegalArgumentException("Invalid token", e);
        }
    }

    public String getTenantIdFromToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet().getStringClaim("tenant_id");
        } catch (Exception e) {
            log.error("Failed to extract tenant_id from token", e);
            throw new IllegalArgumentException("Invalid token", e);
        }
    }
}
