package com.security.system.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/admin")
public class AdminController {

    @GetMapping("/stats")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('ADMIN_ACCESS')")
    public ResponseEntity<Map<String, Object>> getAdminStats(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> stats = new HashMap<>();
        stats.put("status", "SUCCESS");
        stats.put("message", "Welcome, system administrator! Access granted to protected statistics.");
        stats.put("timestamp", LocalDateTime.now().toString());

        stats.put("authenticatedUser", jwt.getSubject());
        stats.put("tenantId", jwt.getClaimAsString("tenant_id"));
        stats.put("assignedRoles", jwt.getClaimAsStringList("roles"));
        stats.put("assignedPermissions", jwt.getClaimAsStringList("permissions"));

        stats.put("activeDatabaseConnections", 12);
        stats.put("cachingEngine", "Redis with local ConcurrentHashMap fallback");
        stats.put("tokenVerificationLatencyMs", "< 1ms (Local memory key verification)");

        return ResponseEntity.ok(stats);
    }
}
