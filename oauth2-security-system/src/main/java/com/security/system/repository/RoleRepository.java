package com.security.system.repository;

import com.security.system.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    List<Role> findAllByTenantId(String tenantId);
    Optional<Role> findByIdAndTenantId(Long id, String tenantId);
    Optional<Role> findByRoleNameAndTenantId(String roleName, String tenantId);
}
