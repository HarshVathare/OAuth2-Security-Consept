package com.codewithHarsh.SpringSecurity.SpringConfig;

//This is the Helper Class

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
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
}
