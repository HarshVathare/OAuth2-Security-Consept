package com.codewithHarsh.SpringSecurity.Service;

import com.codewithHarsh.SpringSecurity.DTO.LoginRequest;
import com.codewithHarsh.SpringSecurity.DTO.LoginResponse;
import com.codewithHarsh.SpringSecurity.DTO.RegesterRequest;
import com.codewithHarsh.SpringSecurity.DTO.UserResponse;
import com.codewithHarsh.SpringSecurity.Entity.User;
import com.codewithHarsh.SpringSecurity.Entity.UserRole;
import com.codewithHarsh.SpringSecurity.Repository.UserRepository;
import com.codewithHarsh.SpringSecurity.SpringConfig.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    public @Nullable UserResponse registerData(RegesterRequest regesterRequest) {
       Optional<User> ExistingUser = userRepository.findByEmail(regesterRequest.getEmail());

       if(ExistingUser.isPresent()) {
           throw new IllegalArgumentException("User Already Exists ..!");
       }

        User user = User.builder()
                .username(regesterRequest.getUsername())
                .firstName(regesterRequest.getFirstName())
                .lastName(regesterRequest.getLastName())
                .email(regesterRequest.getEmail())
                .password(passwordEncoder.encode(regesterRequest.getPassword()))
                .role(UserRole.USER)
                .build();

        User savedUser = userRepository.save(user);

       return new UserResponse(
               savedUser.getId(),
               savedUser.getUsername(),
               savedUser.getEmail(),
               savedUser.getCreatedAt());
    }

    public @Nullable LoginResponse login(LoginRequest loginRequest) {

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail(),
                            loginRequest.getPassword()
                    )
            );

            // Get authenticated user (usually UserDetails)
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            // Generate JWT token
            String token = jwtUtils.generateTokenFromUsername(userDetails);

            System.out.println("Generated JWT: " + token);

            // ✅ Fetch full user from DB
            User user = userRepository.findByEmail(userDetails.getUsername())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            return new LoginResponse(
                    token,
                    user.getId(),
                    user.getEmail()
            );

        } catch (BadCredentialsException e) {
            throw new IllegalArgumentException("Invalid email or password!");
        } catch (Exception e) {
            throw new RuntimeException("Login failed: " + e.getMessage());
        }
    }


//    public UserResponse registerData(RegesterRequest regesterRequest) {
//        User user = User.builder()
//                .email(regesterRequest.getEmail())
//                .firstName(regesterRequest.getFirstName())
//                .lastName(regesterRequest.getLastName())
//                .username(regesterRequest.getUsername())
//                .password(passwordEncoder.encode(regesterRequest.getPassword()))
//                .build();
//
//        User savedUser = userRepository.save(user);
//        return mapedToResponse(savedUser);
//    }
//
//    private @Nullable UserResponse mapedToResponse(User savedUser) {
//
//        UserResponse response = new UserResponse();
//
//        response.setId(savedUser.getId());
//        response.setUsername(savedUser.getUsername());
//        response.setEmail(savedUser.getEmail());
//        response.setCreatedAt(savedUser.getCreatedAt());
//        return response;
//    }
}
