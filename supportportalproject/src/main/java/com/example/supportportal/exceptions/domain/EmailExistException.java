package com.example.supportportal.exceptions.domain;

/** Create account, but email already exist for current user **/

public class EmailExistException extends Exception {
    public EmailExistException(String message){
        super(message);
    }
}
