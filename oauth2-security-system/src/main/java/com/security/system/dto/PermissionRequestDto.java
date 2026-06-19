package com.security.system.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class PermissionRequestDto {
    @NotBlank(message = "Permission name is required")
    @Size(max = 50, message = "Permission name must not exceed 50 characters")
    private String permissionName;

    @Size(max = 255, message = "Description must not exceed 255 characters")
    private String description;
}
