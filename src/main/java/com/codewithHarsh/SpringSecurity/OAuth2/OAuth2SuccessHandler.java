package com.codewithHarsh.SpringSecurity.OAuth2;

import com.codewithHarsh.SpringSecurity.DTO.LoginResponse;
import com.codewithHarsh.SpringSecurity.Service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final AuthService authService;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException {

        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;

        OAuth2User oAuth2User = token.getPrincipal();
        String registrationId = token.getAuthorizedClientRegistrationId();

        ResponseEntity<LoginResponse> loginResponse =
                authService.handleOAuth2LoginRequest(oAuth2User, registrationId);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");

        objectMapper.writeValue(response.getWriter(), loginResponse.getBody());
    }
}







//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request,
//                                        HttpServletResponse response,
//                                        Authentication authentication)
//            throws IOException, ServletException {
//
//        // ✅ Ensure correct authentication type
//        if (!(authentication instanceof OAuth2AuthenticationToken token)) {
//            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid OAuth2 Authentication");
//            return;
//        }
//
//        // ✅ Extract OAuth2 user safely
//        OAuth2User oAuth2User = token.getPrincipal();
//        String registrationId = token.getAuthorizedClientRegistrationId();
//
//        // ✅ Call service
//        ResponseEntity<LoginResponse> loginResponse =
//                authService.handleOAuth2LoginRequest(oAuth2User, registrationId);
//
//        // ✅ Prepare response
//        response.setStatus(loginResponse.getStatusCode().value());
//        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//
//        // ✅ Write JSON response
//        objectMapper.writeValue(response.getWriter(), loginResponse.getBody());
//    }
