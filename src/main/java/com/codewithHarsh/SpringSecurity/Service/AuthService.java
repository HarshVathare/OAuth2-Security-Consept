package com.codewithHarsh.SpringSecurity.Service;

import com.codewithHarsh.SpringSecurity.DTO.LoginRequest;
import com.codewithHarsh.SpringSecurity.DTO.LoginResponse;
import com.codewithHarsh.SpringSecurity.DTO.RegesterRequest;
import com.codewithHarsh.SpringSecurity.DTO.UserResponse;
import com.codewithHarsh.SpringSecurity.Entity.AuthProviderType;
import com.codewithHarsh.SpringSecurity.Entity.User;
import com.codewithHarsh.SpringSecurity.Entity.UserRole;
import com.codewithHarsh.SpringSecurity.Repository.UserRepository;
import com.codewithHarsh.SpringSecurity.SpringConfig.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;

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

    public ResponseEntity<LoginResponse> handleOAuth2LoginRequest(OAuth2User oAuth2User, String registrationId) {
        AuthProviderType providerType = jwtUtils.getProviderTypeFromRegistrationId(registrationId);
        String providerId = jwtUtils.determineProviderIdFromOAuth2User(oAuth2User, registrationId);

        User user = (User) userRepository.findByProviderIdAndProviderType(providerId, providerType).orElse(null);
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        User emailUser = userRepository.findByEmail(email).orElse(null);

        if(user == null && emailUser == null) {
            // signup flow:
            String username = jwtUtils.determineUsernameFromOAuth2User(oAuth2User, registrationId, providerId);
            user = signUpInternal(new SignUpRequestDto(username, null, name, Set.of(RoleType.USER)), providerType, providerId);
        } else if(user != null) {
            if(email != null && !email.isBlank() && !email.equals(user.getUsername())) {
                user.setUsername(email);
                userRepository.save(user);
            }
        } else {
            throw new BadCredentialsException("This email is already registered with provider "+emailUser.getProviderType());
        }

        LoginResponse loginResponseDto = new LoginResponse(jwtUtils.generateTokenFromUsername(), user.getId());
        return ResponseEntity.ok(loginResponseDto);
    }

}
