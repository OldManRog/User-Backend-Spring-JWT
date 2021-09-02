package com.example.supportportal.exceptions.domain;


/** Create account, but Username already exist  **/

public class UsernameExistException extends Exception {
    public UsernameExistException(String message) {
        super(message);
    }
}
