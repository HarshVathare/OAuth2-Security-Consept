package com.codewithHarsh.SpringSecurity.DTO;

import jakarta.persistence.Column;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserResponse {
    private String id;

    private String username;

    private String email;

    private LocalDateTime createdAt;
}
