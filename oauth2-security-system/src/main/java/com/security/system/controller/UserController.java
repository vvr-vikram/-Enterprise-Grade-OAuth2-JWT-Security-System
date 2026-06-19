package com.security.system.controller;

import com.security.system.dto.UserRequestDto;
import com.security.system.dto.UserResponseDto;
import com.security.system.model.Role;
import com.security.system.model.User;
import com.security.system.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('READ_USER')")
    public ResponseEntity<List<UserResponseDto>> getAllUsers() {
        List<UserResponseDto> users = userService.getAllUsers().stream()
                .map(this::mapToResponseDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(users);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('READ_USER')")
    public ResponseEntity<UserResponseDto> getUserById(@PathVariable Long id) {
        return userService.getUserById(id)
                .map(user -> ResponseEntity.ok(mapToResponseDto(user)))
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    @PreAuthorize("hasAuthority('WRITE_USER')")
    public ResponseEntity<UserResponseDto> createUser(@Valid @RequestBody UserRequestDto request) {
        User user = User.builder()
                .username(request.getUsername())
                .password(request.getPassword())
                .email(request.getEmail())
                .isActive(request.getIsActive())
                .build();

        User createdUser = userService.createUser(user, request.getRoles());
        return ResponseEntity.status(HttpStatus.CREATED).body(mapToResponseDto(createdUser));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('WRITE_USER')")
    public ResponseEntity<UserResponseDto> updateUser(@PathVariable Long id, @Valid @RequestBody UserRequestDto request) {
        User userDetails = User.builder()
                .email(request.getEmail())
                .password(request.getPassword())
                .isActive(request.getIsActive())
                .build();

        User updatedUser = userService.updateUser(id, userDetails, request.getRoles());
        return ResponseEntity.ok(mapToResponseDto(updatedUser));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ADMIN_ACCESS')")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    private UserResponseDto mapToResponseDto(User user) {
        return UserResponseDto.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .isActive(user.getIsActive())
                .tenantId(user.getTenantId())
                .roles(user.getRoles().stream().map(Role::getRoleName).collect(Collectors.toSet()))
                .build();
    }
}
