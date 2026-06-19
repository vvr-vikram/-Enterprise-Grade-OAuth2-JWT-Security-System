package com.security.system.controller;

import com.security.system.dto.PermissionRequestDto;
import com.security.system.model.Permission;
import com.security.system.service.PermissionService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/permissions")
public class PermissionController {

    private final PermissionService permissionService;

    public PermissionController(PermissionService permissionService) {
        this.permissionService = permissionService;
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('ADMIN_ACCESS')")
    public ResponseEntity<List<Permission>> getAllPermissions() {
        return ResponseEntity.ok(permissionService.getAllPermissions());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('ADMIN_ACCESS')")
    public ResponseEntity<Permission> getPermissionById(@PathVariable Long id) {
        return permissionService.getPermissionById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('ADMIN_ACCESS')")
    public ResponseEntity<Permission> createPermission(@Valid @RequestBody PermissionRequestDto request) {
        Permission permission = Permission.builder()
                .permissionName(request.getPermissionName())
                .description(request.getDescription())
                .build();
        Permission created = permissionService.createPermission(permission);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('ADMIN_ACCESS')")
    public ResponseEntity<Permission> updatePermission(@PathVariable Long id, @Valid @RequestBody PermissionRequestDto request) {
        Permission permissionDetails = Permission.builder()
                .permissionName(request.getPermissionName())
                .description(request.getDescription())
                .build();
        Permission updated = permissionService.updatePermission(id, permissionDetails);
        return ResponseEntity.ok(updated);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('ADMIN_ACCESS')")
    public ResponseEntity<Void> deletePermission(@PathVariable Long id) {
        permissionService.deletePermission(id);
        return ResponseEntity.noContent().build();
    }
}
