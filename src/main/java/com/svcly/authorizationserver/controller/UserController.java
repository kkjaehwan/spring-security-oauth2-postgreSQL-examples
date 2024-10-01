/*
 * (C)2024 - Author: Jaehwan Kim (kkjaehwan@gmail.com)
 * 
 * This file is part of the Svcly Authorization Server project.
 * 
 * This code handles user authentication and authorization services.
 */
package com.svcly.authorizationserver.controller;

import com.svcly.authorizationserver.dto.UserRegistrationDTO;
import com.svcly.authorizationserver.service.CustomUserDetailsService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * This controller handles user-related endpoints such as user registration. It exposes an API to
 * register users with their email and password via a POST request.
 */
@RestController
@RequestMapping("/users")
@AllArgsConstructor
public class UserController {

  // CustomUserDetailsService handles user-related business logic
  private final CustomUserDetailsService userService;

  /**
   * Endpoint to handle user registration. Receives the user's email and password in JSON format.
   * Calls the user service to register the user and returns a success message if successful, or an
   * error message if an exception occurs.
   *
   * @param userRegistrationDTO Contains the user's registration details (email, password)
   * @return ResponseEntity containing a success or error message
   */
  @PostMapping("/register")
  public ResponseEntity<String> registerUser(@RequestBody UserRegistrationDTO userRegistrationDTO) {
    try {
      userService.registerUser(userRegistrationDTO); // Call the service to register the user
      return ResponseEntity.ok("User registered successfully"); // Success response
    } catch (RuntimeException e) {
      return ResponseEntity.badRequest()
          .body(e.getMessage()); // Error response with exception message
    }
  }
}
