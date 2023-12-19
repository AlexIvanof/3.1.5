package com.example.security.demo.service;

import com.example.security.demo.model.User;

import java.util.List;

public interface UserService {

    List<User> getAllUsers();
    User findByUsername(String username);

    void save(User user);
    void delete(Long id);
    void update(User user);

    User findUserById(Long id);

}
