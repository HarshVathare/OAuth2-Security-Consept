package com.codewithHarsh.SpringSecurity.DTO;

import jakarta.persistence.Column;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RegesterRequest {

    private String username;

    private String firstName;

    private String lastName;

    private String email;

    private String password;
}
