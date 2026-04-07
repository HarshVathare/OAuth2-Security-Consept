package com.codewithHarsh.SpringSecurity.DTO;

import jakarta.persistence.Column;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RegesterRequest {

    private String username;

    private String firstName;

    private String lastName;

    private String email;

    private String password;

    public <E> RegesterRequest(String username, Object o, String name, Set<E> user) {
    }
}
