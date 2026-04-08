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
import jakarta.transaction.Transactional;
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

    public User signUpInternal(RegesterRequest request,
                               AuthProviderType providerType,
                               String providerId) {

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("User already exists");
        }

        if (providerType == AuthProviderType.EMAIL && request.getPassword() == null) {
            throw new IllegalArgumentException("Password is required for email registration");
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .password(
                        providerType == AuthProviderType.EMAIL
                                ? passwordEncoder.encode(request.getPassword())
                                : null
                )
                .providerType(providerType)
                .providerId(providerId)
                .role(UserRole.USER)
                .build();

        return userRepository.save(user);
    }

    public @Nullable UserResponse registerData(RegesterRequest regesterRequest) {

        User user = signUpInternal(regesterRequest, AuthProviderType.EMAIL, null);

        return new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getCreatedAt());
    }

    public LoginResponse login(LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),
                        loginRequest.getPassword()
                )
        );

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String token = jwtUtils.generateTokenFromUsername(userDetails);

        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        return new LoginResponse(token, user.getId(), user.getEmail());
    }

    @Transactional
    public ResponseEntity<LoginResponse> handleOAuth2LoginRequest(OAuth2User oAuth2User,
                                                                  String registrationId) {

        AuthProviderType providerType =
                jwtUtils.getProviderTypeFromRegistrationId(registrationId);

        String providerId =
                jwtUtils.determineProviderIdFromOAuth2User(oAuth2User, registrationId);

        String email = jwtUtils.extractEmail(oAuth2User, registrationId);
        String name = oAuth2User.getAttribute("name");

        // ⚠️ GitHub case (email can be null)
        if (email == null || email.isBlank()) {
            email = providerId + "@oauth.com"; // fallback
        }

        User user = (User) userRepository
                .findByProviderIdAndProviderType(providerId, providerType)
                .orElse(null);

        User emailUser = userRepository.findByEmail(email).orElse(null);

        // ✅ CASE 1: New User
        if (user == null && emailUser == null) {

            user = User.builder()
                    .username(email)
                    .email(email)
                    .firstName(name)
                    .password(null)
                    .providerType(providerType)
                    .providerId(providerId)
                    .role(UserRole.USER)
                    .build();

            user = userRepository.save(user);
        }

        // ❌ CASE 2: Email exists but different provider
        else if (user == null) {
            throw new BadCredentialsException(
                    "Account already exists with " + emailUser.getProviderType()
            );
        }

        // ✅ CASE 3: Existing OAuth user → login
        // nothing needed

        // 🔥 Generate JWT
        UserDetails userDetails = org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password("")
                .authorities(user.getAuthorities())
                .build();

        String token = jwtUtils.generateTokenFromUsername(userDetails);

        return ResponseEntity.ok(
                new LoginResponse(token, user.getId(), user.getEmail())
        );
    }
}





