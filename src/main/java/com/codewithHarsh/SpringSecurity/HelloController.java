package com.codewithHarsh.SpringSecurity;

import com.codewithHarsh.SpringSecurity.DTO.LoginRequest;
import com.codewithHarsh.SpringSecurity.DTO.LoginResponse;
import com.codewithHarsh.SpringSecurity.DTO.RegesterRequest;
import com.codewithHarsh.SpringSecurity.DTO.UserResponse;
import com.codewithHarsh.SpringSecurity.Service.AuthService;
import com.codewithHarsh.SpringSecurity.SpringConfig.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class HelloController {

    @Autowired
    AuthenticationManager authenticationManager;

    private final AuthService authService;

    @Autowired
    JwtUtils jwtUtils;

    @GetMapping("/hello")
    public String sayHello(){
        return "hello harsh ..!";
    }

    @GetMapping("/admin/hello")
    public String sayhello() {
        return "hello admin ..!";
    }

    @GetMapping("/user/hello")
    public String sayuser() {
        return "hello user ..!";
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> registerData(@RequestBody RegesterRequest regesterRequest) {
        return ResponseEntity.ok(authService.registerData(regesterRequest));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(authService.login(loginRequest));
    }
}
