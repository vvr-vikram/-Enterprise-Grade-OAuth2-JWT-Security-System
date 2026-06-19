-- Database initialization script for oauth2_security_db

CREATE DATABASE IF NOT EXISTS oauth2_security_db;
USE oauth2_security_db;

-- 1. Tenants Table
CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Users Table (tenant-isolated)
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(100) NOT NULL,
    tenant_id VARCHAR(50) NOT NULL,
    email VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_username_tenant UNIQUE (username, tenant_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- 3. Roles Table (tenant-isolated)
CREATE TABLE IF NOT EXISTS roles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL,
    tenant_id VARCHAR(50) NOT NULL,
    description VARCHAR(255),
    CONSTRAINT uq_role_tenant UNIQUE (role_name, tenant_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- 4. Permissions Table (global/reusable catalog)
CREATE TABLE IF NOT EXISTS permissions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    permission_name VARCHAR(50) NOT NULL UNIQUE,
    description VARCHAR(255)
);

-- 5. User-Roles Mapping Table
CREATE TABLE IF NOT EXISTS user_roles (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

-- 6. Role-Permissions Mapping Table
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id BIGINT NOT NULL,
    permission_id BIGINT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

-- 7. Refresh Tokens Table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(255) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    expiry_date TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 8. Audit Logs Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    username VARCHAR(100) NOT NULL,
    tenant_id VARCHAR(50),
    ip_address VARCHAR(45),
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_users_tenant_username ON users(tenant_id, username);
CREATE INDEX idx_roles_tenant_name ON roles(tenant_id, role_name);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);

-- Seed Data --

-- Tenants
INSERT INTO tenants (id, name) VALUES ('tenant-a', 'Enterprise Tenant A') ON DUPLICATE KEY UPDATE name=values(name);
INSERT INTO tenants (id, name) VALUES ('tenant-b', 'Enterprise Tenant B') ON DUPLICATE KEY UPDATE name=values(name);

-- Permissions
INSERT INTO permissions (id, permission_name, description) VALUES 
(1, 'READ_USER', 'Ability to view user details'),
(2, 'WRITE_USER', 'Ability to create/edit user details'),
(3, 'DELETE_USER', 'Ability to remove user accounts'),
(4, 'ADMIN_ACCESS', 'Full access to administrative operations')
ON DUPLICATE KEY UPDATE permission_name=values(permission_name);

-- Roles (tenant-a)
INSERT INTO roles (id, role_name, tenant_id, description) VALUES 
(1, 'ROLE_ADMIN', 'tenant-a', 'Administrator for Tenant A'),
(2, 'ROLE_USER', 'tenant-a', 'Standard User for Tenant A')
ON DUPLICATE KEY UPDATE role_name=values(role_name);

-- Roles (tenant-b)
INSERT INTO roles (id, role_name, tenant_id, description) VALUES 
(3, 'ROLE_ADMIN', 'tenant-b', 'Administrator for Tenant B'),
(4, 'ROLE_USER', 'tenant-b', 'Standard User for Tenant B')
ON DUPLICATE KEY UPDATE role_name=values(role_name);

-- Role-Permissions (tenant-a admin gets all; user gets read only)
INSERT INTO role_permissions (role_id, permission_id) VALUES 
(1, 1), (1, 2), (1, 3), (1, 4), -- tenant-a admin
(2, 1)                           -- tenant-a user
ON DUPLICATE KEY UPDATE role_id=role_id;

-- Role-Permissions (tenant-b admin gets all; user gets read only)
INSERT INTO role_permissions (role_id, permission_id) VALUES 
(3, 1), (3, 2), (3, 3), (3, 4), -- tenant-b admin
(4, 1)                           -- tenant-b user
ON DUPLICATE KEY UPDATE role_id=role_id;

-- Users (BCrypt hash for password 'password123' is '$2a$10$eK04qNW9fgywDVWfBOhscOyQf5hiZBB4YKQnRIWt8JaCbgjj8v/VW')
-- tenant-a: admin_a, user_a
INSERT INTO users (id, username, password, tenant_id, email, is_active) VALUES 
(1, 'admin_a', '$2a$10$eK04qNW9fgywDVWfBOhscOyQf5hiZBB4YKQnRIWt8JaCbgjj8v/VW', 'tenant-a', 'admin_a@tenant-a.com', true),
(2, 'user_a', '$2a$10$eK04qNW9fgywDVWfBOhscOyQf5hiZBB4YKnRIWt8JaCbgjj8v/VW', 'tenant-a', 'user_a@tenant-a.com', true)
ON DUPLICATE KEY UPDATE username=values(username);

-- tenant-b: admin_b, user_b
INSERT INTO users (id, username, password, tenant_id, email, is_active) VALUES 
(3, 'admin_b', '$2a$10$eK04qNW9fgywDVWfBOhscOyQf5hiZBB4YKQnRIWt8JaCbgjj8v/VW', 'tenant-b', 'admin_b@tenant-b.com', true),
(4, 'user_b', '$2a$10$eK04qNW9fgywDVWfBOhscOyQf5hiZBB4YKQnRIWt8JaCbgjj8v/VW', 'tenant-b', 'user_b@tenant-b.com', true)
ON DUPLICATE KEY UPDATE username=values(username);

-- User-Roles
INSERT INTO user_roles (user_id, role_id) VALUES 
(1, 1), -- admin_a -> ROLE_ADMIN (tenant-a)
(2, 2), -- user_a -> ROLE_USER (tenant-a)
(3, 3), -- admin_b -> ROLE_ADMIN (tenant-b)
(4, 4)  -- user_b -> ROLE_USER (tenant-b)
ON DUPLICATE KEY UPDATE user_id=user_id;
