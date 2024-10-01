/*
 * (C)2024 - Author: Jaehwan Kim (kkjaehwan@gmail.com)
 * 
 * This file is part of the Svcly Authorization Server project.
 * 
 * This code handles user authentication and authorization services.
 */
package com.svcly.authorizationserver.service;

import com.svcly.authorizationserver.dto.UserRegistrationDTO;
import com.svcly.authorizationserver.entity.CustomUser;
import com.svcly.authorizationserver.entity.Role;
import com.svcly.authorizationserver.repository.RoleRepository;
import com.svcly.authorizationserver.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Service class that implements {@link UserDetailsService} to handle user-related business logic.
 * This service is responsible for loading user details for authentication purposes, as well as
 * registering new users by processing user registration data.
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {

  @Autowired private UserRepository userRepository;

  @Autowired private RoleRepository roleRepository;

  @Autowired private PasswordEncoder passwordEncoder;

  /**
   * Loads a user by their username or email for authentication. This method is required by the
   * {@link UserDetailsService} interface and is used during the login process.
   *
   * @param username The username or email used to authenticate the user.
   * @return The {@link UserDetails} object containing user information.
   * @throws UsernameNotFoundException If the user with the given username or email is not found.
   */
  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    CustomUser user = userRepository.findByEmail(username).orElse(null);
    if (user == null) {
      throw new UsernameNotFoundException("User not found");
    }
    return user;
  }

  /**
   * Registers a new user based on the provided {@link UserRegistrationDTO} data. The method checks
   * if the email is already in use, encrypts the user's password, assigns a default role
   * (ROLE_USER), and saves the user in the repository.
   *
   * @param userRegistrationDTO Contains the registration details such as email, password, and
   *     username.
   * @return The saved {@link CustomUser} entity.
   * @throws RuntimeException If the email is already in use or the default role is not found.
   */
  public CustomUser registerUser(UserRegistrationDTO userRegistrationDTO) {
    // Check if the email is already in use
    if (userRepository.findByEmail(userRegistrationDTO.getEmail()).isPresent()) {
      throw new RuntimeException("Email is already in use");
    }

    // Create a new user and encrypt the password
    CustomUser user = new CustomUser();
    user.setEmail(userRegistrationDTO.getEmail());
    user.setPassword(
        passwordEncoder.encode(userRegistrationDTO.getPassword())); // Encrypt the password
    user.setUsername(userRegistrationDTO.getUsername());

    // Assign the default role (ROLE_USER)
    Role userRole =
        roleRepository
            .findByName("ROLE_USER")
            .orElseThrow(() -> new RuntimeException("Role not found"));
    user.getRoles().add(userRole);

    // Save and return the new user
    return userRepository.save(user);
  }
}
