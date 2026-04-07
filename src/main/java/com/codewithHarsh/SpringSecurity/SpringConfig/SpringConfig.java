package com.codewithHarsh.SpringSecurity.SpringConfig;

//Centralized config file

import com.codewithHarsh.SpringSecurity.OAuth2.OAuth2SuccessHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import javax.sql.DataSource;

@Configuration
@Slf4j
@EnableWebSecurity
public class SpringConfig {

    @Autowired
    DataSource dataSource;

    @Autowired
    AuthTokenFilter authTokenFilter;

    @Autowired
    CustomUserDetails customUserDetails;

//    @Autowired
//    OAuth2SuccessHandler oAuth2SuccessHandler;

    @Autowired
    HandlerExceptionResolver handlerExceptionResolver;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, OAuth2SuccessHandler oAuth2SuccessHandler) throws Exception {

        http
                .csrf(csrf -> csrf.disable())

                .authorizeHttpRequests(auth -> auth
                        // Public endpoints
                        .requestMatchers("/login", "/register", "/hello").permitAll()

                        // Role-based endpoints
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")

                        // Any other request
                        .anyRequest().authenticated()

                )
//                .oauth2Login(oauth2-> oauth2.defaultSuccessUrl("/hello",true))
//                .oauth2Login(oauth2 -> oauth2
//                        .successHandler(oAuth2SuccessHandler)
//                )

        ;
//                        .formLogin(Customizer.withDefaults());

        // JWT filter (enable later)
         http.addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);
http.oauth2Login(oAuth2 -> oAuth2
                .failureHandler((request, response, exception) -> {
                    log.error("OAuth2 error: {}", exception.getMessage());
                    handlerExceptionResolver.resolveException(request, response, null, exception);
                })
                .successHandler(oAuth2SuccessHandler)
        );
//        http
//                .oauth2Login(oauth -> oauth
//                        .successHandler(oAuth2SuccessHandler)
//                );
        return http.build();
    }


    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(); //return instance
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) {
        return builder.getAuthenticationManager();
    }

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }
}

