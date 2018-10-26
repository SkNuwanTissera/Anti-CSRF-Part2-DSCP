package com.csrf.auth.service;

import javax.servlet.http.HttpServletResponse;

public interface SecurityService {
    String findLoggedInUsername();

    void autologin(String username, String password, HttpServletResponse response);
}
