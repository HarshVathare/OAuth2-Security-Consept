package com.codewithHarsh.SpringSecurity.Error;

import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ExceptionHandling {

    // 1 => User Not Found Exception
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<Apierror> UserNotfoundException(UsernameNotFoundException ex) {
        Apierror apierror = new Apierror(HttpStatus.NOT_FOUND, "User Not found Exception By Username "+ex.getMessage());

        return new ResponseEntity<>(apierror, HttpStatus.NOT_FOUND);
    }

    // 2 Authentication Exception
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Apierror> AuthenticationException(AuthenticationException ex) {
        Apierror apierror = new Apierror(HttpStatus.UNAUTHORIZED, "Authentication Failed ..! "+ex.getMessage());

        return new ResponseEntity<>(apierror, HttpStatus.UNAUTHORIZED);
    }

    // 3 Jwt Exception
    @ExceptionHandler(JwtException.class)
    public ResponseEntity<Apierror> JwtException(JwtException ex) {
        Apierror apierror = new Apierror(HttpStatus.UNAUTHORIZED, "Invalid JWT Token ..! "+ex.getMessage());

        return new ResponseEntity<>(apierror, HttpStatus.UNAUTHORIZED);
    }

    // 4 Access Denied ( Not Permission ) Exception
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Apierror> AccessDeniedException(AccessDeniedException ex) {
        Apierror apierror = new Apierror(HttpStatus.FORBIDDEN, "Access denied : UnSufficient Permissions ..! "+ex.getMessage());

        return new ResponseEntity<>(apierror, HttpStatus.FORBIDDEN);
    }

    // 5 Exception only ( Internal Server Error )
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Apierror> Exception(Exception ex) {
        Apierror apierror = new Apierror(HttpStatus.INTERNAL_SERVER_ERROR, "An Unaccepted error occurred ..! "+ex.getMessage());

        return new ResponseEntity<>(apierror, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
