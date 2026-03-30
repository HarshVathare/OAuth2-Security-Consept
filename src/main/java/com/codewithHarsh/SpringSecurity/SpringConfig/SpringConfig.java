package com.codewithHarsh.SpringSecurity.SpringConfig;

//Centralized config file

import com.codewithHarsh.SpringSecurity.Service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SpringConfig {

    @Autowired
    DataSource dataSource;

    @Autowired
    AuthTokenFilter authTokenFilter;

    @Autowired
    CustomUserDetailsService customUserDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

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

                // Enable authentication provider
                .authenticationProvider(authenticationProvider(customUserDetailsService));

        // JWT filter (enable later)
         http.addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

//    @Autowired
//    AuthTokenFilter authTokenFilter;

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) {
//        http.csrf(AbstractHttpConfigurer::disable)
//                .authorizeHttpRequests(httprequest->
//                httprequest.requestMatchers("/admin/**").hasRole("ADMIN")
//                                .requestMatchers("/user/**").hasRole("USER")
//
//                .anyRequest().permitAll()
//        );
////        http.addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);
//        return http.build();
//    }

    @Bean
    public AuthenticationProvider authenticationProvider(
            CustomUserDetailsService userDetailsService) {

        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider(userDetailsService); // ✅ REQUIRED

        provider.setPasswordEncoder(passwordEncoder());

        return provider;
    }

  //  @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails user1 = User.withUsername("abc")
//                .password(passwordEncoder().encode("abc"))
//                .roles("USER")
//                .build();
//
//        UserDetails user2 = User.withUsername("xyz")
//                .password(passwordEncoder().encode("xyz"))
//                .roles("USER")
//                .build();
//
//        UserDetails admin = User.withUsername("admin2")
//                .password(passwordEncoder().encode("admin2"))
//                .roles("ADMIN")
//                .build();
//
////        return new InMemoryUserDetailsManager(user1, user2); // data store in memory not DB
//        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
//        if(!userDetailsManager.userExists(user1.getUsername())){
//            userDetailsManager.createUser(user1);
//        }
//
//        if(!userDetailsManager.userExists(user2.getUsername())){
//            userDetailsManager.createUser(user2);
//        }
//
//        if(!userDetailsManager.userExists(admin.getUsername())){
//            userDetailsManager.createUser(admin);
//        }
//
//        return userDetailsManager;
//    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(); //return instance
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) {
        return builder.getAuthenticationManager();
    }
}
