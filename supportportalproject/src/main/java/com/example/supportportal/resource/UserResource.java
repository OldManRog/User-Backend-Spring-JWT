package com.example.supportportal.resource;

import com.example.supportportal.domain.User;
import com.example.supportportal.domain.UserPrincipal;
import com.example.supportportal.exceptions.domain.*;
import com.example.supportportal.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static org.springframework.http.HttpStatus.OK;

@RestController
@RequestMapping("/api/v1/user")
public class UserResource extends ExceptionHandling {

    @Autowired
    public UserResource(UserService userService, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
    }

    private final UserService userService;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User user) throws UserNotFoundException, EmailExistException, UsernameExistException {
       return ResponseEntity.ok(userService.register(user.getFirstName(),user.getLastName(),user.getUsername(),user.getEmail()));
    }

    @PostMapping("/login")
    public ResponseEntity<User> login(@RequestBody User user) throws UserNotFoundException {
        authenticate(user.getUsername(),user.getPassword());
        User loginUser = userService.findByUsername(user.getUsername());
        UserPrincipal userPrincipal = new UserPrincipal(loginUser);
        HttpHeaders jwtHeader = userService.getJwtHeaders(userPrincipal);
//        return ResponseEntity.ok().headers(jwtHeader).body(loginUser);
        return new ResponseEntity<>(loginUser,jwtHeader,OK);
    }

    @GetMapping("/GET/users")
    public ResponseEntity<List<User>>getAllUsers(){
        return ResponseEntity.ok(userService.getUsers());
    }

    @GetMapping("/GET/userByEmail")
    public ResponseEntity<User>findUserByEmail(@RequestBody User user) throws EmailNotFoundException {
        return ResponseEntity.ok(userService.findByEmail(user.getEmail()));
    }

    @GetMapping("/GET/userByUsername")
    public ResponseEntity<User>findUserByUsername(@RequestBody User user) throws UserNotFoundException {
        return ResponseEntity.ok(userService.findByUsername(user.getUsername()));
    }

    public void authenticate (String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username,password));
    }


}
