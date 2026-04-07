package com.codewithHarsh.SpringSecurity.OAuth2;

import com.codewithHarsh.SpringSecurity.Entity.User;
import com.codewithHarsh.SpringSecurity.Repository.UserRepository;
import com.codewithHarsh.SpringSecurity.SpringConfig.CustomUserDetails;
import com.codewithHarsh.SpringSecurity.SpringConfig.JwtUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;

@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;

    public OAuth2SuccessHandler(UserRepository userRepository, JwtUtils jwtUtils) {
        this.userRepository = userRepository;
        this.jwtUtils = jwtUtils;
    }


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();

// 🔥 Extract provider info
        String email = oauthUser.getAttribute("email");
        String name = oauthUser.getAttribute("name");

// 👉 GitHub fallback
        if (email == null) {
            email = oauthUser.getAttribute("login"); // GitHub username
        }

// 👉 Microsoft fallback
        if (email == null) {
            email = oauthUser.getAttribute("preferred_username");
        }

// 👉 Safety check
        if (email == null) {
            throw new RuntimeException("Email not found from OAuth2 provider");
        }

// ✅ Save or fetch user from DB
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(newUser.getEmail());
//                    newUser.setName(name != null ? name : email);
                    if (name != null) {
                        newUser.setUsername(name);
                    } else {
                        newUser.setUsername(newUser.getEmail());
                    }
//                    newUser.set("OAUTH2"); // optional
                    return userRepository.save(newUser);
                });

// ✅ Convert to UserDetails
        UserDetails userDetails = new CustomUserDetails(
                user.getEmail(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

// 🔥 Generate JWT
        String token = jwtUtils.generateTokenFromUsername(userDetails);

// ✅ Send response
        response.setContentType("application/json");
        response.getWriter().write("""
    {
        "token": "%s",
        "username": "%s"
    }
""".formatted(token, userDetails.getUsername()));
    }
}
