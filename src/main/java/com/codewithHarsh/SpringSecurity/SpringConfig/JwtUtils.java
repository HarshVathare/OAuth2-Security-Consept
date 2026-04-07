package com.codewithHarsh.SpringSecurity.SpringConfig;

//This is the Helper Class

import com.codewithHarsh.SpringSecurity.Entity.AuthProviderType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
@Slf4j
public class JwtUtils {



    private String jwtSecret = "ghjyfghtdsfrhghjuiojklghjukjdftuyjkijklofghuksdfxcvjkliuykh";

    private int JwtExpiration = 172800000; // for 48 hr



    public String getJwtFromHeaders(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if(bearerToken != null && bearerToken.startsWith("Bearer "))
            return bearerToken.substring(7);
        return null;
    }

    public String generateTokenFromUsername(UserDetails userDetails) {
        String userName = userDetails.getUsername();

        return Jwts.builder()
                .subject(userName)
                .claim("roles",userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList()
                )
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + JwtExpiration))
                .signWith(getSecreatKey())
                .compact();
    }

    public Boolean validateJwtToken(String JwtToken) {
        try{
            Jwts.parser().verifyWith(getSecreatKey()).build()
                    .parseSignedClaims(JwtToken);
        } catch (JwtException e) {
            throw new RuntimeException(e);
        }
        return true;
    }

    private SecretKey getSecreatKey() {
//        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    public String getUsernameFromToken(String jwt) {
        return Jwts.parser().verifyWith(getSecreatKey()).build()
                .parseSignedClaims(jwt)
                .getPayload()
                .getSubject();
    }

    public Claims getAllClaims(String jwt) {
        return Jwts.parser().verifyWith(getSecreatKey()).build()
                .parseSignedClaims(jwt)
                .getPayload();
    }

    //add Oauth2 methods
    public AuthProviderType getProviderTypeFromRegistrationId(String registrationId) {
        return switch (registrationId.toLowerCase()) {
            case "google" -> AuthProviderType.GOOGLE;
            case "github" -> AuthProviderType.GITHUB;
            case "facebook" -> AuthProviderType.FACEBOOK;
            case "twitter" -> AuthProviderType.TWITTER;
            default -> throw new IllegalArgumentException("Unsupported OAuth2 provider: " + registrationId);
        };
    }


    public String determineProviderIdFromOAuth2User(OAuth2User oAuth2User, String registrationId) {
        String providerId = switch (registrationId.toLowerCase()) {
            case "google" -> oAuth2User.getAttribute("sub");
            case "github" -> oAuth2User.getAttribute("id").toString();

            default -> {
                log.error("Unsupported OAuth2 provider: {}", registrationId);
                throw new IllegalArgumentException("Unsupported OAuth2 provider: " + registrationId);
            }
        };

        if (providerId == null || providerId.isBlank()) {
            log.error("Unable to determine providerId for provider: {}", registrationId);
            throw new IllegalArgumentException("Unable to determine providerId for OAuth2 login");
        }
        return providerId;
    }

    public String determineUsernameFromOAuth2User(OAuth2User oAuth2User, String registrationId, String providerId) {
        String email = oAuth2User.getAttribute("email");
        if (email != null && !email.isBlank()) {
            return email;
        }
        return switch (registrationId.toLowerCase()) {
            case "google" -> oAuth2User.getAttribute("sub");
            case "github" -> oAuth2User.getAttribute("login");
            default -> providerId;
        };
    }


}
