package com.security.system.service;

import com.security.system.model.AuditLog;
import com.security.system.repository.AuditLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuditLogService {

    private static final Logger log = LoggerFactory.getLogger(AuditLogService.class);

    private final AuditLogRepository auditLogRepository;

    public AuditLogService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @Transactional
    public void logEvent(String eventType, String username, String tenantId, String ipAddress, String details) {
        log.info("AUDIT EVENT: [{}] - User: {} | Tenant: {} | IP: {} | Details: {}",
                eventType, username, tenantId, ipAddress, details);

        try {
            AuditLog auditLog = AuditLog.builder()
                    .eventType(eventType)
                    .username(username)
                    .tenantId(tenantId)
                    .ipAddress(ipAddress)
                    .details(details)
                    .build();
            auditLogRepository.save(auditLog);
        } catch (Exception e) {
            log.error("Failed to persist audit log", e);
        }
    }
}
