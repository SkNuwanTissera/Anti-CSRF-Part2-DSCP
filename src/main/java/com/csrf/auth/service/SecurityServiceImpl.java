package com.csrf.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.UUID;

@Service
public class SecurityServiceImpl implements SecurityService{

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(SecurityServiceImpl.class);

    @Override
    public String findLoggedInUsername() {
        Object userDetails = SecurityContextHolder.getContext().getAuthentication().getDetails();
        if (userDetails instanceof UserDetails) {
            return ((UserDetails)userDetails).getUsername();
        }

        return null;
    }

    @Override
    public void autologin(String username, String password, HttpServletResponse response) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());

        authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        if (usernamePasswordAuthenticationToken.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            /**
             * Implementation For Synchronizer Token Pattern to Prevent CSRF
             */
            HashMap<String,String> session_csrf_ =new HashMap<String,String>();

            String csrf_value = UUID.randomUUID().toString()+System.currentTimeMillis();
            String session_value = UUID.randomUUID().toString()+System.currentTimeMillis();

            Cookie csrfCookie = new Cookie("csrf", csrf_value);
            Cookie session = new Cookie("session", session_value);
            Cookie userCookie = new Cookie("username", username);

            session_csrf_.put(session_value,csrf_value);

            response.addCookie(csrfCookie);
            response.addCookie(userCookie);
            response.addCookie(session);
            logger.debug(String.format("Auto login %s successfully!", username));
        }
    }
}
