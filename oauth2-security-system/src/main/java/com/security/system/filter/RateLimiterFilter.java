package com.security.system.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

@Component
public class RateLimiterFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(RateLimiterFilter.class);

    @Value("${app.rate-limiting.global-max-requests:60}")
    private int maxRequestsPerMinute;

    private static final long WINDOW_SIZE_SECONDS = 60;

    private final ConcurrentHashMap<String, Queue<Long>> ipRequestTimestamps = new ConcurrentHashMap<>();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String ipAddress = getClientIp(httpRequest);
        long now = Instant.now().getEpochSecond();
        long windowStart = now - WINDOW_SIZE_SECONDS;

        Queue<Long> timestamps = ipRequestTimestamps.computeIfAbsent(ipAddress, k -> new ConcurrentLinkedQueue<>());

        // Clean out older records
        while (!timestamps.isEmpty() && timestamps.peek() < windowStart) {
            timestamps.poll();
        }

        if (timestamps.size() >= maxRequestsPerMinute) {
            log.warn("Rate limit exceeded for IP: {}. Requests: {}", ipAddress, timestamps.size());
            httpResponse.setStatus(429); // Too Many Requests
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write("{\"error\": \"Too Many Requests\", \"message\": \"Rate limit exceeded. Please try again later.\"}");
            return;
        }

        timestamps.add(now);
        chain.doFilter(request, response);
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty()) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }
}
