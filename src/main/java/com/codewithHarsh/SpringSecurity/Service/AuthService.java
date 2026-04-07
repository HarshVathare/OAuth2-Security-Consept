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

        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        User user = (User) userRepository
                .findByProviderIdAndProviderType(providerId, providerType)
                .orElse(null);

        User emailUser = userRepository.findByEmail(email).orElse(null);

        if (user == null && emailUser == null) {

            user = signUpInternal(
                    new RegesterRequest(email, null, name, null),
                    providerType,
                    providerId
            );

        } else if (user == null) {
            throw new BadCredentialsException(
                    "Already registered with " + emailUser.getProviderType()
            );
        }

        // ✅ Create UserDetails
        UserDetails userDetails = org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())
                .password("")
                .authorities(user.getAuthorities())
                .build();

        String token = jwtUtils.generateTokenFromUsername(userDetails);

        return ResponseEntity.ok(
                new LoginResponse(token, user.getId(), user.getEmail())
        );
    }
}




//@Service
//@RequiredArgsConstructor
//public class AuthService {
//
//    private final UserRepository userRepository;
//    private final PasswordEncoder passwordEncoder;
//    private final AuthenticationManager authenticationManager;
//    private final JwtUtils jwtUtils;
//
//    public User signUpInternal(RegesterRequest regesterRequest, AuthProviderType authProviderType, String providerId) {
//        User user = userRepository.findByEmail(regesterRequest.getEmail()).orElse(null);
//
//        if(user != null) throw new IllegalArgumentException("User already exists");
//
//         user = User.builder()
//                .username(regesterRequest.getUsername())
//                .firstName(regesterRequest.getFirstName())
//                .lastName(regesterRequest.getLastName())
//                .email(regesterRequest.getEmail())
//                .password(passwordEncoder.encode(regesterRequest.getPassword()))
//                .role(UserRole.USER)
//                .build();
//
//        User savedUser = userRepository.save(user);
//
//        if(authProviderType == AuthProviderType.EMAIL) {
//            user.setPassword(passwordEncoder.encode(regesterRequest.getPassword()));
//        }
//
//        user = userRepository.save(savedUser);
//
//        return user;
//    }
//
//
//    public @Nullable UserResponse registerData(RegesterRequest regesterRequest) {
//
//        User user = signUpInternal(regesterRequest, AuthProviderType.EMAIL, null);
//
//       return new UserResponse(
//               user.getId(),
//               user.getUsername(),
//               user.getEmail(),
//               user.getCreatedAt());
//    }
//
//    public @Nullable LoginResponse login(LoginRequest loginRequest) {
//
//        try {
//            Authentication authentication = authenticationManager.authenticate(
//                    new UsernamePasswordAuthenticationToken(
//                            loginRequest.getEmail(),
//                            loginRequest.getPassword()
//                    )
//            );
//
//            // Get authenticated user (usually UserDetails)
//            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
//
//            // Generate JWT token
//            String token = jwtUtils.generateTokenFromUsername(userDetails);
//
//            System.out.println("Generated JWT: " + token);
//
//            // ✅ Fetch full user from DB
//            User user = userRepository.findByEmail(userDetails.getUsername())
//                    .orElseThrow(() -> new RuntimeException("User not found"));
//
//            return new LoginResponse(
//                    token,
//                    user.getId(),
//                    user.getEmail()
//            );
//
//        } catch (BadCredentialsException e) {
//            throw new IllegalArgumentException("Invalid email or password!");
//        } catch (Exception e) {
//            throw new RuntimeException("Login failed: " + e.getMessage());
//        }
//    }
//
//    @Transactional
//    public ResponseEntity<LoginResponse> handleOAuth2LoginRequest(OAuth2User oAuth2User, String registrationId) {
//        AuthProviderType providerType = jwtUtils.getProviderTypeFromRegistrationId(registrationId);
//        String providerId = jwtUtils.determineProviderIdFromOAuth2User(oAuth2User, registrationId);
//
//        User user = (User) userRepository.findByProviderIdAndProviderType(providerId, providerType).orElse(null);
//        String email = oAuth2User.getAttribute("email");
//        String name = oAuth2User.getAttribute("name");
//
//        User emailUser = userRepository.findByEmail(email).orElse(null);
//
//        if(user == null && emailUser == null) {
//            // signup flow:
//            String username = jwtUtils.determineUsernameFromOAuth2User(oAuth2User, registrationId, providerId);
//            user = signUpInternal(new RegesterRequest(username, null, name, Set.of(UserRole.USER)), providerType, providerId);
//        } else if(user != null) {
//            if(email != null && !email.isBlank() && !email.equals(user.getUsername())) {
//                user.setUsername(email);
//                userRepository.save(user);
//            }
//        } else {
//            throw new BadCredentialsException("This email is already registered with provider "+emailUser.getProviderType());
//        }
//
//        // ✅ Convert User → UserDetails
//        UserDetails userDetails = org.springframework.security.core.userdetails.User
//                .withUsername(user.getUsername())
//                .password("") // not needed for OAuth
//                .authorities(user.getAuthorities())
//                .build();
//
//        LoginResponse loginResponseDto = new LoginResponse(jwtUtils.generateTokenFromUsername(userDetails), user.getId(), user.getEmail());
//        return ResponseEntity.ok(loginResponseDto);
//    }
//
//}
