package com.security.system.service;

import com.security.system.dto.LoginRequest;
import com.security.system.dto.RefreshRequest;
import com.security.system.dto.TokenResponse;
import com.security.system.model.RefreshToken;
import com.security.system.model.User;
import com.security.system.repository.RefreshTokenRepository;
import com.security.system.repository.UserRepository;
import com.security.system.security.TokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenProvider tokenProvider;
    private final TokenBlacklistService blacklistService;
    private final RateLimiterService rateLimiterService;
    private final AuditLogService auditLogService;

    @Value("${app.jwt.expiration:900}")
    private long jwtExpirationInSeconds;

    @Value("${app.jwt.refresh-expiration:604800}")
    private long refreshExpirationInSeconds;

    public AuthService(UserRepository userRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       PasswordEncoder passwordEncoder,
                       TokenProvider tokenProvider,
                       TokenBlacklistService blacklistService,
                       RateLimiterService rateLimiterService,
                       AuditLogService auditLogService) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenProvider = tokenProvider;
        this.blacklistService = blacklistService;
        this.rateLimiterService = rateLimiterService;
        this.auditLogService = auditLogService;
    }

    @Transactional
    public TokenResponse login(LoginRequest request, String ipAddress) {
        String username = request.getUsername();
        String tenantId = request.getTenantId();

        if (rateLimiterService.isBlocked(ipAddress, username, tenantId)) {
            auditLogService.logEvent("LOGIN_BLOCKED", username, tenantId, ipAddress, "Brute force block active");
            throw new LockedException("Too many login attempts. Temporary block active.");
        }

        Optional<User> userOpt = userRepository.findByUsernameAndTenantId(username, tenantId);
        if (userOpt.isEmpty()) {
            rateLimiterService.recordLoginFailure(ipAddress, username, tenantId);
            auditLogService.logEvent("LOGIN_FAILURE", username, tenantId, ipAddress, "User not found");
            throw new BadCredentialsException("Invalid credentials or tenant ID.");
        }

        User user = userOpt.get();

        if (!user.getIsActive()) {
            auditLogService.logEvent("LOGIN_FAILURE", username, tenantId, ipAddress, "Account inactive");
            throw new LockedException("User account is inactive.");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            rateLimiterService.recordLoginFailure(ipAddress, username, tenantId);
            auditLogService.logEvent("LOGIN_FAILURE", username, tenantId, ipAddress, "Invalid password");
            throw new BadCredentialsException("Invalid credentials or tenant ID.");
        }

        rateLimiterService.recordLoginSuccess(ipAddress, username, tenantId);

        String accessToken = tokenProvider.generateAccessToken(user);
        RefreshToken refreshToken = createRefreshToken(user);

        auditLogService.logEvent("LOGIN_SUCCESS", username, tenantId, ipAddress, "Successful authentication");

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .expiresIn(jwtExpirationInSeconds)
                .tenantId(tenantId)
                .build();
    }

    @Transactional
    public TokenResponse refresh(RefreshRequest request, String ipAddress) {
        String reqToken = request.getRefreshToken();

        RefreshToken oldRefreshToken = refreshTokenRepository.findByToken(reqToken)
                .orElseThrow(() -> {
                    auditLogService.logEvent("REFRESH_FAILURE", "UNKNOWN", request.getTenantId(), ipAddress, "Token not found");
                    return new IllegalArgumentException("Invalid refresh token");
                });

        User user = oldRefreshToken.getUser();

        if (oldRefreshToken.getRevoked()) {
            refreshTokenRepository.deleteByUserId(user.getId());
            auditLogService.logEvent("TOKEN_REUSE_ATTEMPT", user.getUsername(), user.getTenantId(), ipAddress,
                    "Revoked refresh token was reused. Cleared all user sessions.");
            throw new SecurityException("Refresh token reuse detected! All sessions revoked.");
        }

        if (oldRefreshToken.isExpired()) {
            auditLogService.logEvent("REFRESH_FAILURE", user.getUsername(), user.getTenantId(), ipAddress, "Refresh token expired");
            throw new IllegalArgumentException("Refresh token expired. Please login again.");
        }

        oldRefreshToken.setRevoked(true);
        refreshTokenRepository.save(oldRefreshToken);

        String newAccessToken = tokenProvider.generateAccessToken(user);
        RefreshToken newRefreshToken = createRefreshToken(user);

        auditLogService.logEvent("TOKEN_REFRESH", user.getUsername(), user.getTenantId(), ipAddress, "Tokens refreshed");

        return TokenResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken.getToken())
                .expiresIn(jwtExpirationInSeconds)
                .tenantId(user.getTenantId())
                .build();
    }

    @Transactional
    public void logout(String authHeader, String ipAddress) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Invalid authorization header");
        }

        String token = authHeader.substring(7);
        if (tokenProvider.validateToken(token)) {
            String username = tokenProvider.getUsernameFromToken(token);
            String tenantId = tokenProvider.getTenantIdFromToken(token);

            blacklistService.blacklistToken(token);

            Optional<User> userOpt = userRepository.findByUsernameAndTenantId(username, tenantId);
            userOpt.ifPresent(user -> refreshTokenRepository.deleteByUserId(user.getId()));

            auditLogService.logEvent("LOGOUT", username, tenantId, ipAddress, "Logged out successfully");
        } else {
            throw new IllegalArgumentException("Invalid or expired token");
        }
    }

    private RefreshToken createRefreshToken(User user) {
        refreshTokenRepository.deleteByUserId(user.getId());

        RefreshToken refreshToken = RefreshToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .expiryDate(LocalDateTime.now().plusSeconds(refreshExpirationInSeconds))
                .revoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }
}
