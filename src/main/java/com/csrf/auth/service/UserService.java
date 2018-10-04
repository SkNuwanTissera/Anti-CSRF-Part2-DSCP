package com.csrf.auth.service;

import com.csrf.auth.model.User;

public interface UserService {
    void save(User user);

    User findByUsername(String username);
}
