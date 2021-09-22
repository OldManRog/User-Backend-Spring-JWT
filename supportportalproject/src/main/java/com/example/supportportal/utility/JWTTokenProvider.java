package com.example.supportportal.utility;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.supportportal.constant.SecurityConstant;
import static com.example.supportportal.constant.SecurityConstant.*;
import static java.util.Arrays.stream;

import com.example.supportportal.domain.UserPrincipal;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;


import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JWTTokenProvider {

    String secret = "secret"; //THE SECRET KEY SHOULD BE IN A DIFFERENT FILE THAT WE CAN CALL FROM. THIS IS ONLY FOR EASE OF DEVELOPMENT AND TESTING

    /** This will be called at login **/
    public String generateJwtToken(UserPrincipal userPrincipal){
            String[] claims = getClaimsFromUser(userPrincipal);
        return JWT.create().withIssuer(GET_ARRAYS_LLC).withAudience(GET_ARRAYS_ADMINISTRATION)
                    .withIssuedAt(new Date()).withSubject(userPrincipal.getUsername())
                    .withArrayClaim(AUTHORITIES,claims).withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                    .sign(Algorithm.HMAC512(secret.getBytes()));
    }

    /** This will get the authorities from the claims extracted from the token  **/
    public List<GrantedAuthority>getAuthorities(String token){
        String[] claims = getClaimsFromToken(token);
        return stream(claims).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    /** Gets authentication once we verity the token. It allows us to tell spring web security that this user is authenticated **/
    public Authentication getAuthentication(String username, List<GrantedAuthority> authorities, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(username,null,authorities);
        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        return usernamePasswordAuthenticationToken;
    }

    /** This function will make sure that the token is valid, username is good, and token is not expired after being verified **/
    public boolean isTokenValid(String username, String token){
        JWTVerifier verifier = getJWTVerifier();
        return StringUtils.isNotEmpty(username) && !isTokenExpired(verifier, token);
    }


    /** This function will get the username from the token**/
    public String getSubject(String token){
        JWTVerifier verifier = getJWTVerifier();
        return verifier.verify(token).getSubject();
    }

    /** Function checks that token is not expired. if before expiration date is before new date(), then it will return TRUE (Token is expired) **/
    private boolean isTokenExpired(JWTVerifier verifier, String token) {
        Date expiration = verifier.verify(token).getExpiresAt();
        return  expiration.before(new Date());
    }




    /**  These are helper methods that help out with the functions from above  **/


    /** This verifies the token with the algorithm & with the issuer. It throws an exception if the token cannot be verified **/
    private JWTVerifier getJWTVerifier() {
        JWTVerifier verifier;
        try {
            Algorithm algorithm = Algorithm.HMAC512(secret);
            verifier = JWT.require(algorithm).withIssuer(GET_ARRAYS_LLC).build();
        } catch (JWTVerificationException exception) {
            throw new JWTVerificationException(TOKEN_CANNOT_BE_VERIFIED);
        }
        return verifier;
    }


     /**  extracts the claims from the token once the token is verified  **/
    private String[] getClaimsFromToken(String token) {
        JWTVerifier verifier = getJWTVerifier();
        return verifier.verify(token).getClaim(AUTHORITIES).asArray(String.class);
    }


    /** This function extracts the claims from the user.
     * It covers each authority from the user into a granted Authority and adds them to a list of authorities **/
    private String[] getClaimsFromUser(UserPrincipal user) {
        List<String> authorities = new ArrayList<>();
        for (GrantedAuthority grantedAuthority : user.getAuthorities()){
            authorities.add(grantedAuthority.getAuthority());
        }
        return  authorities.toArray(new String[0]);
    }


}
