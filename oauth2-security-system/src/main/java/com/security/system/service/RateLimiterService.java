package com.security.system.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Service
public class RateLimiterService {

    private static final Logger log = LoggerFactory.getLogger(RateLimiterService.class);

    private final StringRedisTemplate redisTemplate;

    @Value("${app.redis.enabled:false}")
    private boolean redisEnabled;

    @Value("${app.rate-limiting.enabled:true}")
    private boolean rateLimitingEnabled;

    @Value("${app.rate-limiting.max-attempts:5}")
    private int maxAttempts;

    @Value("${app.rate-limiting.block-duration-seconds:300}")
    private long blockDurationSeconds;

    private final Map<String, AttemptRecord> inMemoryAttempts = new ConcurrentHashMap<>();

    private static class AttemptRecord {
        int attempts;
        long blockedUntil;

        AttemptRecord() {
            this.attempts = 0;
            this.blockedUntil = 0;
        }
    }

    public RateLimiterService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    private String getRateLimitKey(String ip, String username, String tenantId) {
        return "ratelimit:login:" + ip + ":" + tenantId + ":" + username;
    }

    public boolean isBlocked(String ip, String username, String tenantId) {
        if (!rateLimitingEnabled) {
            return false;
        }

        String key = getRateLimitKey(ip, username, tenantId);

        if (redisEnabled) {
            try {
                String blockedVal = redisTemplate.opsForValue().get(key + ":blocked");
                if (blockedVal != null) {
                    return true;
                }
            } catch (Exception e) {
                log.warn("Redis isBlocked check failed. Using in-memory check", e);
            }
        }

        AttemptRecord record = inMemoryAttempts.get(key);
        if (record != null && record.blockedUntil > System.currentTimeMillis()) {
            return true;
        }
        return false;
    }

    public void recordLoginFailure(String ip, String username, String tenantId) {
        if (!rateLimitingEnabled) {
            return;
        }

        String key = getRateLimitKey(ip, username, tenantId);

        if (redisEnabled) {
            try {
                String val = redisTemplate.opsForValue().get(key);
                int attempts = val == null ? 0 : Integer.parseInt(val);
                attempts++;

                if (attempts >= maxAttempts) {
                    redisTemplate.opsForValue().set(key + ":blocked", "true", blockDurationSeconds, TimeUnit.SECONDS);
                    redisTemplate.delete(key);
                    log.warn("Brute-force limit hit for: {}. Blocked for {}s.", key, blockDurationSeconds);
                } else {
                    redisTemplate.opsForValue().set(key, String.valueOf(attempts), blockDurationSeconds, TimeUnit.SECONDS);
                }
                return;
            } catch (Exception e) {
                log.warn("Redis recordLoginFailure failed. Using in-memory store", e);
            }
        }

        AttemptRecord record = inMemoryAttempts.computeIfAbsent(key, k -> new AttemptRecord());
        record.attempts++;
        if (record.attempts >= maxAttempts) {
            record.blockedUntil = System.currentTimeMillis() + (blockDurationSeconds * 1000);
            log.warn("In-Memory: Brute-force limit hit for: {}. Blocked for {}s.", key, blockDurationSeconds);
        }
    }

    public void recordLoginSuccess(String ip, String username, String tenantId) {
        String key = getRateLimitKey(ip, username, tenantId);

        if (redisEnabled) {
            try {
                redisTemplate.delete(key);
                redisTemplate.delete(key + ":blocked");
                return;
            } catch (Exception e) {
                log.warn("Redis recordLoginSuccess failed", e);
            }
        }

        inMemoryAttempts.remove(key);
    }

    @Scheduled(fixedRate = 600000)
    public void cleanupMemory() {
        long now = System.currentTimeMillis();
        inMemoryAttempts.entrySet().removeIf(entry -> {
            AttemptRecord rec = entry.getValue();
            return rec.blockedUntil <= now && rec.attempts < maxAttempts;
        });
    }
}
