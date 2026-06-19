package com.security.system.service;

import com.security.system.model.Permission;
import com.security.system.model.Role;
import com.security.system.repository.PermissionRepository;
import com.security.system.repository.RoleRepository;
import com.security.system.tenant.TenantContext;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
public class RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    public RoleService(RoleRepository roleRepository, PermissionRepository permissionRepository) {
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
    }

    public List<Role> getAllRoles() {
        String tenantId = TenantContext.getTenantId();
        return roleRepository.findAllByTenantId(tenantId);
    }

    public Optional<Role> getRoleById(Long id) {
        String tenantId = TenantContext.getTenantId();
        return roleRepository.findByIdAndTenantId(id, tenantId);
    }

    @Transactional
    public Role createRole(Role role, Set<String> permissionNames) {
        String tenantId = TenantContext.getTenantId();
        
        if (roleRepository.findByRoleNameAndTenantId(role.getRoleName(), tenantId).isPresent()) {
            throw new IllegalArgumentException("Role '" + role.getRoleName() + "' already exists in tenant '" + tenantId + "'");
        }

        role.setTenantId(tenantId);

        Set<Permission> permissions = new HashSet<>();
        if (permissionNames != null) {
            for (String permName : permissionNames) {
                Permission permission = permissionRepository.findByPermissionName(permName)
                        .orElseThrow(() -> new IllegalArgumentException("Permission '" + permName + "' not found"));
                permissions.add(permission);
            }
        }
        role.setPermissions(permissions);

        return roleRepository.save(role);
    }

    @Transactional
    public Role updateRole(Long id, Role roleDetails, Set<String> permissionNames) {
        String tenantId = TenantContext.getTenantId();
        Role existingRole = roleRepository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Role not found with id " + id));

        existingRole.setRoleName(roleDetails.getRoleName());
        existingRole.setDescription(roleDetails.getDescription());

        if (permissionNames != null) {
            Set<Permission> permissions = new HashSet<>();
            for (String permName : permissionNames) {
                Permission permission = permissionRepository.findByPermissionName(permName)
                        .orElseThrow(() -> new IllegalArgumentException("Permission '" + permName + "' not found"));
                permissions.add(permission);
            }
            existingRole.setPermissions(permissions);
        }

        return roleRepository.save(existingRole);
    }

    @Transactional
    public void deleteRole(Long id) {
        String tenantId = TenantContext.getTenantId();
        Role existingRole = roleRepository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Role not found with id " + id));
        roleRepository.delete(existingRole);
    }
}
