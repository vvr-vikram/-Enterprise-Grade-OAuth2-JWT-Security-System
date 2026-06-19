package com.security.system.dto;

import lombok.Builder;
import lombok.Data;
import java.util.Set;

@Data
@Builder
public class UserResponseDto {
    private Long id;
    private String username;
    private String email;
    private Boolean isActive;
    private String tenantId;
    private Set<String> roles;
}
