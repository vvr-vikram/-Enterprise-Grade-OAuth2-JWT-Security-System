package com.security.system.service;

import com.security.system.model.Permission;
import com.security.system.repository.PermissionRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
public class PermissionService {

    private final PermissionRepository permissionRepository;

    public PermissionService(PermissionRepository permissionRepository) {
        this.permissionRepository = permissionRepository;
    }

    public List<Permission> getAllPermissions() {
        return permissionRepository.findAll();
    }

    public Optional<Permission> getPermissionById(Long id) {
        return permissionRepository.findById(id);
    }

    @Transactional
    public Permission createPermission(Permission permission) {
        if (permissionRepository.findByPermissionName(permission.getPermissionName()).isPresent()) {
            throw new IllegalArgumentException("Permission '" + permission.getPermissionName() + "' already exists");
        }
        return permissionRepository.save(permission);
    }

    @Transactional
    public Permission updatePermission(Long id, Permission permissionDetails) {
        Permission existingPermission = permissionRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Permission not found with id " + id));
        existingPermission.setPermissionName(permissionDetails.getPermissionName());
        existingPermission.setDescription(permissionDetails.getDescription());
        return permissionRepository.save(existingPermission);
    }

    @Transactional
    public void deletePermission(Long id) {
        Permission existingPermission = permissionRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Permission not found with id " + id));
        permissionRepository.delete(existingPermission);
    }
}
