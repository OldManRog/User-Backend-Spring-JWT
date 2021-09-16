package com.example.supportportal.resource;

import com.example.supportportal.domain.HttpResponse;
import com.example.supportportal.domain.User;
import com.example.supportportal.domain.UserPrincipal;
import com.example.supportportal.exceptions.domain.*;
import com.example.supportportal.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import static com.example.supportportal.constant.FileConstant.*;
import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.MediaType.IMAGE_JPEG_VALUE;

@RestController
@RequestMapping(path = {"/", "/api/v1/user"})
public class UserResource extends ExceptionHandling {

    @Autowired
    public UserResource(UserService userService, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
    }

    private final UserService userService;
    private final AuthenticationManager authenticationManager;

    /**
     * Register User API
     **/
    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User user) throws UserNotFoundException, EmailExistException, UsernameExistException, MessagingException {
        return ResponseEntity.ok(userService.register(user.getFirstName(), user.getLastName(), user.getUsername(), user.getEmail()));
    }

    /**
     * Login API
     **/
    @PostMapping("/login")
    public ResponseEntity<User> login(@RequestBody User user) throws UserNotFoundException {
        authenticate(user.getUsername(), user.getPassword());
        User loginUser = userService.findByUsername(user.getUsername());
        UserPrincipal userPrincipal = new UserPrincipal(loginUser);
        HttpHeaders jwtHeader = userService.getJwtHeaders(userPrincipal);
//        return ResponseEntity.ok().headers(jwtHeader).body(loginUser);
        return new ResponseEntity<>(loginUser, jwtHeader, OK);
    }

    /**
     * get list of users API
     **/
    @GetMapping("/list")
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(userService.getUsers());
    }

    /**
     * get singe user through email API
     **/
    @GetMapping("/GET/email/{email}")
    public ResponseEntity<User> findUserByEmail(@PathVariable("email") String email) throws EmailNotFoundException {
        return new ResponseEntity<>(userService.findByEmail(email), OK);
    }

    /**
     * get single user API
     **/
    @GetMapping("/GET/username/{username}")
    public ResponseEntity<User> findUserByUsername(@PathVariable() String username) throws UserNotFoundException {
        return new ResponseEntity<>(userService.findByUsername(username),OK);
    }


    /**
     * another user adds a user API
     **/
    @PostMapping("/add")
    public ResponseEntity<User> addNewUser(@RequestParam("firstName") String firstName,
                                           @RequestParam("lastName") String lastName,
                                           @RequestParam("username") String username,
                                           @RequestParam("email") String email,
                                           @RequestParam("role") String role,
                                           @RequestParam("isActive") String isActive,
                                           @RequestParam("isNonLocked") String isNonLocked,
                                           @RequestParam(value = "profileImage", required = false) MultipartFile profileImage
    ) throws UserNotFoundException, EmailExistException, MessagingException, IOException, UsernameExistException {
        return ResponseEntity.ok(userService.addNewUser(firstName, lastName, username, email, role, Boolean.parseBoolean(isNonLocked), Boolean.parseBoolean(isActive), profileImage));
    }

    /**
     * update user API
     **/
    @PostMapping("/update")
    public ResponseEntity<User> updateUser(@RequestParam("currentUsername") String currentUsername,
                                           @RequestParam("firstName") String firstName,
                                           @RequestParam("lastName") String lastName,
                                           @RequestParam("username") String username,
                                           @RequestParam("email") String email,
                                           @RequestParam("role") String role,
                                           @RequestParam("isActive") String isActive,
                                           @RequestParam("isNonLocked") String isNonLocked,
                                           @RequestParam(value = "profileImage", required = false) MultipartFile profileImage)
            throws UserNotFoundException, EmailExistException, MessagingException, IOException, NullValuesException, UsernameExistException {
        return ResponseEntity.ok(
                userService.updateUser(currentUsername, firstName, lastName, username, email, role, Boolean.parseBoolean(isNonLocked), Boolean.parseBoolean(isActive), profileImage)
        );
    }

    /**
     * Delete User API
     **/
    @DeleteMapping("/DELETE/{id}")
    @PreAuthorize("hasAnyAuthority('user:delete')")//only users with the authority of delete can call this method
    public ResponseEntity<HttpResponse> deleteUser(@PathVariable("id") Long id) throws UserNotFoundException {
        userService.deleteUser(id);
            return response(OK, "user with id: " + id + " is deleted");

    }

    /**
     * Reset Password API
     **/
    @GetMapping("/resetPassword/{email}")
    public ResponseEntity<HttpResponse> updatePassword(@PathVariable("email") String email) throws EmailNotFoundException, MessagingException {
        userService.resetPassword(email);
        return response(OK, "Password is reset. Please check your email: " + email + " for your new password");
    }

    /**
     * Method to update profile image
     **/
    @PostMapping("/updateProfileImage")
    public ResponseEntity<User> updateProfileImage(@RequestParam("username") String username,
                                                   @RequestParam(value = "profileImage") MultipartFile profileImage)
            throws UserNotFoundException, EmailExistException, MessagingException, IOException, UsernameExistException {
        return ResponseEntity.ok(userService.updateProfileImage(username, profileImage));
    }

    /**
     * Helper Methods
     **/
    private ResponseEntity<HttpResponse> response(HttpStatus httpStatus, String message) {
        return new ResponseEntity<>(
                new HttpResponse(new Date(), httpStatus.value(), httpStatus, httpStatus.getReasonPhrase().toUpperCase(Locale.ROOT), message.toUpperCase(Locale.ROOT)),
                httpStatus
        );
    }

    /** This will grab a photo from the folder **/
    @GetMapping(path = "/image/{username}/{fileName}",produces = IMAGE_JPEG_VALUE)
    public byte[] getProfileImage(@PathVariable("username") String username, @PathVariable("fileName") String fileName) throws IOException {
        return Files.readAllBytes(Paths.get(USER_FOLDER + username + FORWARD_SLASH + fileName));
    }

    /** This will grab a default photo from Robohash **/
    @GetMapping(path = "/image/profile/{username}",produces = IMAGE_JPEG_VALUE)
    public byte[] getTempProfileImage(@PathVariable("username") String username) throws IOException {
        URL url = new URL(TEMP_PROFILE_IMAGE_BASE_URL + username);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try(InputStream inputStream = url.openStream()) {
            int bytesRead;
            byte[] chunk = new byte[1024];
            while((bytesRead = inputStream.read(chunk)) > 0) {
                byteArrayOutputStream.write(chunk,0,bytesRead);
            }
        }
        return byteArrayOutputStream.toByteArray();
    }


    private void authenticate(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }


}
