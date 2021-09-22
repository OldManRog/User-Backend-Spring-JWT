package com.example.supportportal.services;


import com.example.supportportal.domain.User;
import com.example.supportportal.domain.UserPrincipal;
import com.example.supportportal.exceptions.domain.*;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import javax.mail.Multipart;
import java.io.IOException;
import java.util.List;

public interface UserService {
    /**
     * User can register with this method
     **/
    User register(String firstName, String lastName, String userName, String email) throws UserNotFoundException, EmailExistException, UsernameExistException, MessagingException; // Used in User Controller

    /**
     * User can fetch all users with this method
     **/
    List<User> getUsers(); // Used in User Controller

    /**
     * User can fetch a user by username
     **/
    User findByUsername(String username) throws UserNotFoundException; // Used in User Controller

    /**
     * User can fetch a user by email
     **/
    User findByEmail(String email) throws EmailNotFoundException; // Used in User Controller

    /**
     * User can add a new user.
     **/
    User addNewUser(String firstName, String lastName, String userName, String email, String role, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, MessagingException, IOException;

    /**
     * User can update their data by changing their username
     **/
    User updateUser(String currentUsername, String newFirstname, String newLastName, String newUserName, String newEmail, String newRole, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, NullValuesException, MessagingException, IOException;

    /**
     * User can delete themselves or another user can delete them
     **/
    void deleteUser(Long id) throws UserNotFoundException;

    /**
     * User can reset their password
     **/
    void resetPassword(String email) throws EmailNotFoundException, MessagingException;

    /**
     * User can update ONLY their image
     **/
    User updateProfileImage(String username,MultipartFile newProfileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, MessagingException, IOException;

    /**
     * This is a JWT provider method
     **/
    HttpHeaders getJwtHeaders(UserPrincipal userPrincipal); // Used in User Controller


    //    void authenticate(String username, String password); // Used in User Controller
    //    User getByUsername(String username); // Used ONLY in Service (Helper)
    //    User getByEmail(String email); // Used ONLY in Service (Helper)
}
