package com.codewithHarsh.SpringSecurity.Repository;

import com.codewithHarsh.SpringSecurity.Entity.AuthProviderType;
import com.codewithHarsh.SpringSecurity.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {


    Optional<User> findByEmail(String email);


    Optional<Object> findByProviderIdAndProviderType(String providerId, AuthProviderType providerType);
}