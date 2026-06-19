package com.security.system.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class TenantRequestDto {
    @NotBlank(message = "Tenant ID is required")
    @Size(max = 50, message = "Tenant ID must not exceed 50 characters")
    private String id;

    @NotBlank(message = "Tenant name is required")
    @Size(max = 100, message = "Tenant name must not exceed 100 characters")
    private String name;
}
