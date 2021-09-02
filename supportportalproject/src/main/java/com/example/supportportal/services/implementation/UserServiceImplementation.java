package com.example.supportportal.services.implementation;

import com.example.supportportal.domain.User;
import com.example.supportportal.domain.UserPrincipal;
import com.example.supportportal.enumeration.Role;
import com.example.supportportal.exceptions.domain.EmailExistException;
import com.example.supportportal.exceptions.domain.EmailNotFoundException;
import com.example.supportportal.exceptions.domain.UserNotFoundException;
import com.example.supportportal.exceptions.domain.UsernameExistException;
import com.example.supportportal.repository.UserRepository;
import com.example.supportportal.services.LoginAttemptService;
import com.example.supportportal.services.UserService;
import com.example.supportportal.utility.JWTTokenProvider;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutionException;

import static com.example.supportportal.constant.SecurityConstant.JWT_TOKEN_HEADER;
import static com.example.supportportal.constant.UserServiceImpConstants.*;

@Service
@RequiredArgsConstructor
@Transactional
@Qualifier("UserDetailService")
@Slf4j
public class UserServiceImplementation implements UserService, UserDetailsService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JWTTokenProvider jwtTokenProvider;
    private final LoginAttemptService loginAttemptService;


    /**
     * Used to load user for Spring web security to check against
     **/
    @SneakyThrows
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findUserByUsername(username); //JPSQL to fetch username
        if (user == null) {
            log.error("Username {} does not exist", username);
            throw new UsernameNotFoundException(USER_DOES_NOT_EXIST);
        } else {
            validateLoginAttempt(user);
            user.setLastLoginDateDisplay(user.getLastLoginDate());
            user.setLastLoginDate(new Date());
            userRepository.save(user);
            UserPrincipal userPrincipal = new UserPrincipal(user);
            log.info("Returning found user by username {}", username);
            return userPrincipal;
        }
    }

    private void validateLoginAttempt(User user) throws ExecutionException {
        if(user.isNotLocked()) {
            user.setNotLocked(!loginAttemptService.hasExceededMaxAttempt(user.getUsername()));
        } else {
            loginAttemptService.evictUserFromLoginAttemptCache(user.getUsername());
        }
    }

    /**
     * Used for Register API call
     **/
    @Override
    public User register(String firstName, String lastName, String userName, String email) throws UserNotFoundException, EmailExistException, UsernameExistException {
        validateNewUsernameAndEmail(StringUtils.EMPTY, userName, email);
        User user = new User();
        user.setUserID(generateUserId());
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setUsername(userName);
        user.setEmail(email);
        user.setJoinedDate(new Date());
        user.setActive(true);
        user.setNotLocked(true);
        user.setRole(Role.ROLE_USER.name()); //Sets the Role
        user.setAuthorities(Role.ROLE_USER.getAuthorities()); //Sets the authorities from the enum of the role
        String password = generatePassword(); //calls the method to generate password and returns password
        String encodedPassword = encodePassword(password); //encodes the password and returns an encoded password
        user.setPassword(encodedPassword); // we'll set the encoded password as the password
        user.setProfileImageUrl(getTemporaryProfileImageUrl());
        log.info("New User Password {} ", password); //SHOULD NOT LEAVE THIS HERE - ONLY FOR DEBUGGING
        return userRepository.save(user);
    }

    /**
     * Used to generate temp profile image URL for Register API call
     **/
    private String getTemporaryProfileImageUrl() {
        return ServletUriComponentsBuilder.fromCurrentContextPath().path(DEFAULT_USER_IMAGE_PATH).toUriString();
    }

    /**
     * Used to encode password for password generator for Register API call
     **/
    private String encodePassword(String password) {
        return bCryptPasswordEncoder.encode(password);
    }

    /**
     * Used to generate password for Register API call
     **/
    private String generatePassword() {
        return RandomStringUtils.randomAlphanumeric(10);
    }

    /**
     * Used to generate ID for Register API call
     **/
    private String generateUserId() {
        return RandomStringUtils.randomNumeric(10);
    }

    /**
     * Used to validate Register API Call
     **/
    private User validateNewUsernameAndEmail(String currentUsername, String newUsername, String newEmail) throws UserNotFoundException, UsernameExistException, EmailExistException {

        User newUser = getByUsername(newUsername);
        User newEmailAccount = getByEmail(newEmail);

        //Scenario in which the user exist and is trying to update
        if (StringUtils.isNotBlank(currentUsername)) {
            User currentUser = getByUsername(currentUsername);
            if (currentUser == null) {
                throw new UserNotFoundException(USER_DOES_NOT_EXIST + currentUsername);
            }
            if (newUser != null && !currentUser.getId().equals(newUser.getId())) {  //if username is taken, & the currentUser did not update their username to the newUsername
                throw new UsernameExistException(USERNAME_ALREADY_EXIST);
            }

            if (newEmailAccount != null && !currentUser.getId().equals(newEmailAccount.getId())) {  //if email is taken, & the currentUser did not update their username to the newUsername
                throw new EmailExistException(EMAIL_ALREADY_EXIST);
            }
            return currentUser;
        } else {  //If user is new and not already an existing user
            if (newUser != null) {
                throw new UsernameExistException(USERNAME_ALREADY_EXIST); //if user is taken throw exception
            }
            if (newEmailAccount != null) {
                throw new EmailExistException(EMAIL_ALREADY_EXIST); //if email is taken throw exception
            }
            return null;
        }
    }

    /**
     * Used for API call to get all users
     **/
    @Override
    public List<User> getUsers() {
        return userRepository.findAll();
    }

    /**
     * Used for API call to get user by username
     **/
    @Override
    public User findByUsername(String username) throws UserNotFoundException {
        User user = userRepository.findUserByUsername(username);
        if (user == null) {
            throw new UserNotFoundException(USER_DOES_NOT_EXIST);
        }
        return user;
    }

    /**
     * Used for API call to get user by email
     **/
    @Override
    public User findByEmail(String email) throws EmailNotFoundException {
        User user = userRepository.findUserByEmail(email);
        if (user == null) {
            throw new EmailNotFoundException(EMAIL_DOES_NOT_EXIST);
        }
        return user;
    }

    /**
     * Used for validation Method for register and update credentials
     **/
    public User getByUsername(String username) {
        return userRepository.findUserByUsername(username);
    }

    /**
     * Used for validation Method for register and update credentials
     **/
    public User getByEmail(String email) {
        return userRepository.findUserByEmail(email);
    }


    @Override
    public HttpHeaders getJwtHeaders(UserPrincipal userPrincipal) {
         HttpHeaders headers = new HttpHeaders();
         headers.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtToken(userPrincipal));
         return headers;
    }

}
