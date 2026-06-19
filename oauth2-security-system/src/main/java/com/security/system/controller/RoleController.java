package com.security.system.controller;

import com.security.system.dto.RoleRequestDto;
import com.security.system.model.Role;
import com.security.system.service.RoleService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/roles")
public class RoleController {

    private final RoleService roleService;

    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('READ_USER') or hasAuthority('ADMIN_ACCESS')")
    public ResponseEntity<List<Role>> getAllRoles() {
        return ResponseEntity.ok(roleService.getAllRoles());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('READ_USER') or hasAuthority('ADMIN_ACCESS')")
    public ResponseEntity<Role> getRoleById(@PathVariable Long id) {
        return roleService.getRoleById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    @PreAuthorize("hasAuthority('WRITE_USER') or hasAuthority('ADMIN_ACCESS')")
    public ResponseEntity<Role> createRole(@Valid @RequestBody RoleRequestDto request) {
        Role role = Role.builder()
                .roleName(request.getRoleName())
                .description(request.getDescription())
                .build();
        Role created = roleService.createRole(role, request.getPermissions());
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('WRITE_USER') or hasAuthority('ADMIN_ACCESS')")
    public ResponseEntity<Role> updateRole(@PathVariable Long id, @Valid @RequestBody RoleRequestDto request) {
        Role roleDetails = Role.builder()
                .roleName(request.getRoleName())
                .description(request.getDescription())
                .build();
        Role updated = roleService.updateRole(id, roleDetails, request.getPermissions());
        return ResponseEntity.ok(updated);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ADMIN_ACCESS')")
    public ResponseEntity<Void> deleteRole(@PathVariable Long id) {
        roleService.deleteRole(id);
        return ResponseEntity.noContent().build();
    }
}
