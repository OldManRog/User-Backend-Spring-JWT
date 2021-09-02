package com.example.supportportal.services;


import com.example.supportportal.domain.User;
import com.example.supportportal.domain.UserPrincipal;
import com.example.supportportal.exceptions.domain.EmailExistException;
import com.example.supportportal.exceptions.domain.EmailNotFoundException;
import com.example.supportportal.exceptions.domain.UserNotFoundException;
import com.example.supportportal.exceptions.domain.UsernameExistException;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;

public interface UserService {

    User register(String firstName, String lastName, String userName, String email) throws UserNotFoundException, EmailExistException, UsernameExistException; // Used in User Controller

    List<User> getUsers(); // Used in User Controller

    User findByUsername(String username) throws UserNotFoundException; // Used in User Controller

    User findByEmail(String email) throws EmailNotFoundException; // Used in User Controller

//    void authenticate(String username, String password); // Used in User Controller

    HttpHeaders getJwtHeaders(UserPrincipal userPrincipal); // Used in User Controller


    //    User getByUsername(String username); // Used ONLY in Service (Helper)
    //    User getByEmail(String email); // Used ONLY in Service (Helper)
}
