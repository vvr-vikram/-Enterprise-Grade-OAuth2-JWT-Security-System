package com.security.system.service;

import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Service
public class TokenBlacklistService {

    private static final Logger log = LoggerFactory.getLogger(TokenBlacklistService.class);

    private final StringRedisTemplate redisTemplate;

    @Value("${app.redis.enabled:false}")
    private boolean redisEnabled;

    private final Map<String, Long> inMemoryBlacklist = new ConcurrentHashMap<>();

    public TokenBlacklistService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void blacklistToken(String token) {
        long remainingTtlMs = getRemainingTtlMs(token);
        if (remainingTtlMs <= 0) {
            return;
        }

        if (redisEnabled) {
            try {
                redisTemplate.opsForValue().set(token, "blacklisted", remainingTtlMs, TimeUnit.MILLISECONDS);
                log.info("Token blacklisted in Redis for {} ms", remainingTtlMs);
                return;
            } catch (Exception e) {
                log.warn("Redis failed. Falling back to in-memory blacklist", e);
            }
        }

        inMemoryBlacklist.put(token, System.currentTimeMillis() + remainingTtlMs);
        log.info("Token blacklisted in-memory for {} ms", remainingTtlMs);
    }

    public boolean isBlacklisted(String token) {
        if (redisEnabled) {
            try {
                Boolean hasKey = redisTemplate.hasKey(token);
                return hasKey != null && hasKey;
            } catch (Exception e) {
                log.warn("Redis hasKey check failed. Using in-memory check", e);
            }
        }

        Long expiry = inMemoryBlacklist.get(token);
        if (expiry != null) {
            if (expiry > System.currentTimeMillis()) {
                return true;
            } else {
                inMemoryBlacklist.remove(token);
            }
        }
        return false;
    }

    private long getRemainingTtlMs(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            Date expirationTime = signedJWT.getJWTClaimsSet().getExpirationTime();
            if (expirationTime == null) {
                return 0;
            }
            return expirationTime.getTime() - System.currentTimeMillis();
        } catch (Exception e) {
            return 0;
        }
    }

    @Scheduled(fixedRate = 300000)
    public void cleanExpiredTokens() {
        long now = System.currentTimeMillis();
        int before = inMemoryBlacklist.size();
        inMemoryBlacklist.entrySet().removeIf(entry -> entry.getValue() <= now);
        int after = inMemoryBlacklist.size();
        if (before != after) {
            log.info("Cleaned up {} expired blacklisted tokens from memory", before - after);
        }
    }
}
