package com.example.supportportal.exceptions.domain;

/** User not found   **/

public class UserNotFoundException extends Exception {
    public UserNotFoundException(String message) {
        super(message);
    }
}
