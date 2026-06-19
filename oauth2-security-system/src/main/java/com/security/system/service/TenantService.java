package com.security.system.service;

import com.security.system.model.Tenant;
import com.security.system.repository.TenantRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
public class TenantService {

    private final TenantRepository tenantRepository;

    public TenantService(TenantRepository tenantRepository) {
        this.tenantRepository = tenantRepository;
    }

    public List<Tenant> getAllTenants() {
        return tenantRepository.findAll();
    }

    public Optional<Tenant> getTenantById(String id) {
        return tenantRepository.findById(id);
    }

    @Transactional
    public Tenant createTenant(Tenant tenant) {
        if (tenantRepository.existsById(tenant.getId())) {
            throw new IllegalArgumentException("Tenant with ID '" + tenant.getId() + "' already exists");
        }
        return tenantRepository.save(tenant);
    }

    @Transactional
    public Tenant updateTenant(String id, Tenant tenantDetails) {
        Tenant existingTenant = tenantRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Tenant not found with id: " + id));
        existingTenant.setName(tenantDetails.getName());
        return tenantRepository.save(existingTenant);
    }

    @Transactional
    public void deleteTenant(String id) {
        Tenant existingTenant = tenantRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Tenant not found with id: " + id));
        tenantRepository.delete(existingTenant);
    }
}
