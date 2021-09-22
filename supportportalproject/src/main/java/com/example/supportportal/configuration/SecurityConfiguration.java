package com.example.supportportal.configuration;

import com.example.supportportal.constant.SecurityConstant;
import com.example.supportportal.filter.JwtAccesDeniedHandler;
import com.example.supportportal.filter.JwtAuthenticationEntryPoint;
import com.example.supportportal.filter.JwtAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Service;

import static com.example.supportportal.constant.SecurityConstant.PUBLIC_URLS;

@Configuration //we want it to be picked up by Spring
@EnableWebSecurity // Switch off the default web application security configuration and add my own
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor /// for Dependency Injection
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

        private final JwtAuthorizationFilter jwtAuthorizationFilter;
        private final JwtAccesDeniedHandler jwtAccesDeniedHandler;
        private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
        private final UserDetailsService userDetailsService;
        private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().cors().and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().authorizeRequests().antMatchers(PUBLIC_URLS).permitAll()
                .anyRequest().authenticated()
                .and()
                .exceptionHandling().accessDeniedHandler(jwtAccesDeniedHandler)
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .and()
                .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);
    }


    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

}
