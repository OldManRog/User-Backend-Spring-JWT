package com.example.supportportal.exceptions.domain;

/** Try to find email and email can't be found **/

public class EmailNotFoundException extends Exception {
    public EmailNotFoundException(String message){
        super(message);
    }
}
