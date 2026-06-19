package com.security.system.controller;

import com.security.system.dto.TenantRequestDto;
import com.security.system.model.Tenant;
import com.security.system.service.TenantService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/tenants")
public class TenantController {

    private final TenantService tenantService;

    public TenantController(TenantService tenantService) {
        this.tenantService = tenantService;
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('ADMIN_ACCESS')")
    public ResponseEntity<List<Tenant>> getAllTenants() {
        return ResponseEntity.ok(tenantService.getAllTenants());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('ADMIN_ACCESS')")
    public ResponseEntity<Tenant> getTenantById(@PathVariable String id) {
        return tenantService.getTenantById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('ADMIN_ACCESS')")
    public ResponseEntity<Tenant> createTenant(@Valid @RequestBody TenantRequestDto request) {
        Tenant tenant = Tenant.builder()
                .id(request.getId())
                .name(request.getName())
                .build();
        Tenant created = tenantService.createTenant(tenant);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('ADMIN_ACCESS')")
    public ResponseEntity<Tenant> updateTenant(@PathVariable String id, @Valid @RequestBody TenantRequestDto request) {
        Tenant tenantDetails = Tenant.builder()
                .name(request.getName())
                .build();
        Tenant updated = tenantService.updateTenant(id, tenantDetails);
        return ResponseEntity.ok(updated);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('ADMIN_ACCESS')")
    public ResponseEntity<Void> deleteTenant(@PathVariable String id) {
        tenantService.deleteTenant(id);
        return ResponseEntity.noContent().build();
    }
}
