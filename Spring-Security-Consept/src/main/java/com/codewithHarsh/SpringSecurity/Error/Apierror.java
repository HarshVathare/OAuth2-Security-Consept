package com.codewithHarsh.SpringSecurity.Error;

import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;

public class Apierror {
    private LocalDateTime timeStamp;
    private String error;
    private HttpStatus statusCode;

    public Apierror(){
        this.timeStamp = LocalDateTime.now();
    }

    public Apierror(HttpStatus statusCode, String error) {
        this.timeStamp = LocalDateTime.now(); // also fix this
        this.statusCode = statusCode;
        this.error = error;
    }

    public LocalDateTime getTimeStamp() {
        return timeStamp;
    }

    public String getError() {
        return error;
    }

    public HttpStatus getStatusCode() {
        return statusCode;
    }
}

//public class Apierror {
//    private LocalDateTime timeStamp;
//    private String error;
//    private HttpStatus statusCode;
//
//    public Apierror(){
//        this.timeStamp = LocalDateTime.now();
//    }
//
//    public Apierror(HttpStatus statusCode, String error) {
//        this.statusCode = statusCode;
//        this.error = error;
//    }
//}
