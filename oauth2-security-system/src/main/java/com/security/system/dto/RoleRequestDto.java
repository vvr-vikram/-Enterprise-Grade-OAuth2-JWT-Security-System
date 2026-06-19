package com.security.system.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import java.util.Set;

@Data
public class RoleRequestDto {
    @NotBlank(message = "Role name is required")
    @Size(max = 50, message = "Role name must not exceed 50 characters")
    private String roleName;

    @Size(max = 255, message = "Description must not exceed 255 characters")
    private String description;

    private Set<String> permissions;
}
