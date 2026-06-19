package com.security.system.controller;

import com.nimbusds.jose.jwk.JWKSet;
import com.security.system.dto.LoginRequest;
import com.security.system.dto.RefreshRequest;
import com.security.system.dto.TokenResponse;
import com.security.system.security.RsaKeyManager;
import com.security.system.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping
public class AuthController {

    private final AuthService authService;
    private final RsaKeyManager rsaKeyManager;

    public AuthController(AuthService authService, RsaKeyManager rsaKeyManager) {
        this.authService = authService;
        this.rsaKeyManager = rsaKeyManager;
    }

    @PostMapping("/auth/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest loginRequest, HttpServletRequest request) {
        String ipAddress = getClientIp(request);
        TokenResponse response = authService.login(loginRequest, ipAddress);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/auth/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshRequest refreshRequest, HttpServletRequest request) {
        String ipAddress = getClientIp(request);
        TokenResponse response = authService.refresh(refreshRequest, ipAddress);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestHeader("Authorization") String authHeader, HttpServletRequest request) {
        String ipAddress = getClientIp(request);
        authService.logout(authHeader, ipAddress);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    @GetMapping("/oauth2/jwks")
    public Map<String, Object> getJwkSet() {
        return new JWKSet(rsaKeyManager.getRsaKey().toPublicJWK()).toJSONObject();
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty()) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }
}
