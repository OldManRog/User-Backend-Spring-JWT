package com.example.supportportal.services.implementation;

import com.example.supportportal.domain.User;
import com.example.supportportal.domain.UserPrincipal;
import com.example.supportportal.enumeration.Role;
import com.example.supportportal.exceptions.domain.*;
import com.example.supportportal.repository.UserRepository;
import com.example.supportportal.services.EmailService;
import com.example.supportportal.services.LoginAttemptService;
import com.example.supportportal.services.UserService;
import com.example.supportportal.utility.JWTTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.mail.MessagingException;
import javax.mail.Multipart;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutionException;

import static com.example.supportportal.constant.FileConstant.*;
import static com.example.supportportal.constant.SecurityConstant.JWT_TOKEN_HEADER;
import static com.example.supportportal.constant.UserServiceImpConstants.*;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

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
    private final EmailService emailService;


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
        if (user.isNotLocked()) {
            user.setNotLocked(!loginAttemptService.hasExceededMaxAttempt(user.getUsername()));
        } else {
            loginAttemptService.evictUserFromLoginAttemptCache(user.getUsername());
        }
    }

    /**
     * Used for Register API call
     **/
    @Override
    public User register(String firstName, String lastName, String userName, String email) throws UserNotFoundException, EmailExistException, UsernameExistException, MessagingException {
        User user = setDataForUser(null, firstName, lastName, userName, email, null, true, true, true, false, false);
        assert user != null;
        String password = generatePassword(); //calls the method to generate password and returns password
        user.setPassword(encodePassword(password)); // we'll set the encoded password as the password
        emailService.sendNewPasswordEmail(firstName, password, email);
        return userRepository.save(user);
    }

    /**
     * Used for add new user API call
     **/

    @Override
    public User addNewUser(String firstName, String lastName, String userName, String email, String role, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, MessagingException, IOException {
        User newUser = setDataForUser(null, firstName, lastName, userName, email, role, isNonLocked, isActive, false, false, true);
        String password = generatePassword(); //calls the method to generate password and returns password
        assert newUser != null;
        newUser.setPassword(encodePassword(password)); // we'll set the encoded password as the password
        userRepository.save(newUser);
        saveProfileImage(newUser, profileImage);
        emailService.sendNewPasswordEmail(firstName, password, email);
        return newUser;
    }

    /**
     * Used for update user API call
     **/

    @Override
    public User updateUser(String currentUsername, String newFirstname, String newLastName, String newUserName, String newEmail, String newRole, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, MessagingException, IOException {
        User currentUser = setDataForUser(currentUsername, newFirstname, newLastName, newUserName, newEmail, newRole, isNonLocked, isActive, false, true, false);
        assert currentUser != null;
        userRepository.save(currentUser);
        saveProfileImage(currentUser, profileImage);
        return currentUser;
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
     * Used for delete API call
     **/

    @Override
    public void deleteUser(Long id) throws UserNotFoundException {
        if (id == null) {
            throw new UserNotFoundException(USER_DOES_NOT_EXIST);
        } else {
            userRepository.deleteById(id);
        }
    }

    /**
     * Used for Reset password API call
     **/

    @Override
    public void resetPassword(String email) throws EmailNotFoundException, MessagingException {
        User user = userRepository.findUserByEmail(email);
        if (user == null) {
            throw new EmailNotFoundException(EMAIL_DOES_NOT_EXIST);
        }
        String pass = generatePassword();
        user.setPassword(encodePassword(pass));
        userRepository.save(user);
        emailService.sendNewPasswordEmail(user.getFirstName(), pass, user.getEmail());
    }

    /**
     * Used for update profile image API call
     **/

    @Override
    public User updateProfileImage(String username, MultipartFile newProfileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, MessagingException, IOException {
        User user = validateNewUsernameAndEmail(username, null, null);
        saveProfileImage(user, newProfileImage);
        return user;
    }

    // ------ THIS IS THE START OF HELPER METHODS FOR THE SERVICE IMPLEMENTATION -------  //

    /**
     * This method sets the data for the user based on if registering, adding a new user, or updating
     **/

    private User setDataForUser(String currentUsername, String firstname, String lastName, String userName, String email, String role, boolean isNonLocked, boolean isActive, boolean registerFirstTime, boolean updating, boolean addingNewUser) throws UserNotFoundException, EmailExistException, UsernameExistException {
        if (addingNewUser || registerFirstTime) {
            validateNewUsernameAndEmail(StringUtils.EMPTY, userName, email);
            User newUser = new User();
            newUser.setUserID(generateUserId());
            newUser.setFirstName(firstname);
            newUser.setLastName(lastName);
            newUser.setUsername(userName);
            newUser.setEmail(email);
            newUser.setJoinedDate(new Date());
            newUser.setActive(isActive);
            newUser.setNotLocked(isNonLocked);
            if (addingNewUser) {
                newUser.setRole(getRoleEnumName(role).name()); //Sets the Role
                newUser.setAuthorities(getRoleEnumName(role).getAuthorities()); //Sets the authorities from the enum of the role

            } else {
                newUser.setRole(Role.ROLE_USER.name()); //Sets the Role
                newUser.setAuthorities(Role.ROLE_USER.getAuthorities()); //Sets the authorities from the enum of the role

            }
            newUser.setProfileImageUrl(getTemporaryProfileImageUrl(userName));
            return newUser;
        } else if (updating) {
            User currentUser = validateNewUsernameAndEmail(currentUsername, userName, email);
            assert currentUser != null;
            currentUser.setFirstName(firstname);
            currentUser.setLastName(lastName);
            currentUser.setUsername(userName);
            currentUser.setEmail(email);
            currentUser.setNotLocked(isNonLocked);
            currentUser.setActive(isActive);
            currentUser.setRole(getRoleEnumName(role).name());//Sets the Role
            currentUser.setAuthorities(getRoleEnumName(role).getAuthorities()); //Sets the authorities from the enum of the role
            return currentUser;
        }
        return null;
    }


    /**
     * Used by addUser API Method to save the profile image
     **/
    private void saveProfileImage(User user, MultipartFile profileImage) throws IOException, MessagingException {
        if (profileImage != null) { // user/home/supportportal/user/rick
            Path userFolder = Paths.get(USER_FOLDER + user.getUsername()).toAbsolutePath().normalize();
            if (!Files.exists(userFolder)) {
                Files.createDirectories(userFolder);
                log.info(DIRECTORY_CREATED + userFolder);
            }
            Files.deleteIfExists(Paths.get(userFolder + user.getUsername() + DOT + JPG_EXTENSION));
            Files.copy(profileImage.getInputStream(), userFolder.resolve(user.getUsername() + DOT + JPG_EXTENSION), REPLACE_EXISTING);
            user.setProfileImageUrl(setProfileImageUrl(user.getUsername()));
            userRepository.save(user);
        }
    }


    private String setProfileImageUrl(String username) {
        return ServletUriComponentsBuilder.fromCurrentContextPath().path(USER_IMAGE_PATH + username + FORWARD_SLASH + username + DOT + JPG_EXTENSION).toUriString();
    }

    /**
     * Used to generate temp profile image URL for Register API call
     */
    private String getTemporaryProfileImageUrl(String userName) {
        return ServletUriComponentsBuilder.fromCurrentContextPath().path(DEFAULT_USER_IMAGE_PATH + userName).toUriString();
    }

    /**
     * Used by addUser API Method to get the role from the enum name. It will give us access to the name & authoritiesz
     **/
    private Role getRoleEnumName(String role) {
        return Role.valueOf(role.toUpperCase(Locale.ROOT));
    }


    /**
     * Used for validation Method for register and update credentials
     **/
    private User getByUsername(String username) {
        return userRepository.findUserByUsername(username);
    }

    /**
     * Used for validation Method for register and update credentials
     **/
    private User getByEmail(String email) {
        return userRepository.findUserByEmail(email);
    }

    /**
     * Used for generate JWT token
     **/
    @Override
    public HttpHeaders getJwtHeaders(UserPrincipal userPrincipal) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtToken(userPrincipal));
        return headers;
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

}
