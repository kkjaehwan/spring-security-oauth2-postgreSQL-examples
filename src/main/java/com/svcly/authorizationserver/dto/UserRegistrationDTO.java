/*
 * (C)2024 - Author: Jaehwan Kim (kkjaehwan@gmail.com)
 * 
 * This file is part of the Svcly Authorization Server project.
 * 
 * This code handles user authentication and authorization services.
 */
package com.svcly.authorizationserver.dto;

import lombok.Data;

/**
 * Data Transfer Object (DTO) used to capture user registration information. This class contains the
 * necessary fields to register a user, including email, password, and username. It is used to
 * transfer data between the client and the server.
 */
@Data
public class UserRegistrationDTO {

  // The email address of the user being registered
  private String email;

  // The password of the user being registered
  private String password;

  // The username of the user being registered
  private String username;
}
