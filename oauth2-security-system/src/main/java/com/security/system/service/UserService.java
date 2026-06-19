package com.security.system.service;

import com.security.system.model.Role;
import com.security.system.model.User;
import com.security.system.repository.RoleRepository;
import com.security.system.repository.UserRepository;
import com.security.system.tenant.TenantContext;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public UserService(UserRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    public List<User> getAllUsers() {
        String tenantId = TenantContext.getTenantId();
        return userRepository.findAllByTenantId(tenantId);
    }

    public Optional<User> getUserById(Long id) {
        String tenantId = TenantContext.getTenantId();
        return userRepository.findByIdAndTenantId(id, tenantId);
    }

    @Transactional
    public User createUser(User user, Set<String> roleNames) {
        String tenantId = TenantContext.getTenantId();

        if (userRepository.existsByUsernameAndTenantId(user.getUsername(), tenantId)) {
            throw new IllegalArgumentException("Username '" + user.getUsername() + "' already exists in tenant '" + tenantId + "'");
        }

        user.setTenantId(tenantId);
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        Set<Role> roles = new HashSet<>();
        if (roleNames != null) {
            for (String roleName : roleNames) {
                Role role = roleRepository.findByRoleNameAndTenantId(roleName, tenantId)
                        .orElseThrow(() -> new IllegalArgumentException("Role '" + roleName + "' not found for tenant '" + tenantId + "'"));
                roles.add(role);
            }
        }
        user.setRoles(roles);

        return userRepository.save(user);
    }

    @Transactional
    public User updateUser(Long id, User userDetails, Set<String> roleNames) {
        String tenantId = TenantContext.getTenantId();
        User existingUser = userRepository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id " + id));

        existingUser.setEmail(userDetails.getEmail());
        if (userDetails.getPassword() != null && !userDetails.getPassword().isEmpty()) {
            existingUser.setPassword(passwordEncoder.encode(userDetails.getPassword()));
        }
        existingUser.setIsActive(userDetails.getIsActive());

        if (roleNames != null) {
            Set<Role> roles = new HashSet<>();
            for (String roleName : roleNames) {
                Role role = roleRepository.findByRoleNameAndTenantId(roleName, tenantId)
                        .orElseThrow(() -> new IllegalArgumentException("Role '" + roleName + "' not found for tenant '" + tenantId + "'"));
                roles.add(role);
            }
            existingUser.setRoles(roles);
        }

        return userRepository.save(existingUser);
    }

    @Transactional
    public void deleteUser(Long id) {
        String tenantId = TenantContext.getTenantId();
        User user = userRepository.findByIdAndTenantId(id, tenantId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id " + id));
        userRepository.delete(user);
    }
}
