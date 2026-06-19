package com.security.system.repository;

import com.security.system.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    List<User> findAllByTenantId(String tenantId);
    Optional<User> findByIdAndTenantId(Long id, String tenantId);
    Optional<User> findByUsernameAndTenantId(String username, String tenantId);
    boolean existsByUsernameAndTenantId(String username, String tenantId);
}
