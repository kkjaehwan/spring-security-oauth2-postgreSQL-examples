/*
 * (C)2024 - Author: Jaehwan Kim (kkjaehwan@gmail.com)
 * 
 * This file is part of the Svcly Authorization Server project.
 * 
 * This code handles user authentication and authorization services.
 */
package com.svcly.authorizationserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SvclyAuthorizationserverApplication {

  public static void main(String[] args) {
    SpringApplication.run(SvclyAuthorizationserverApplication.class, args);
  }
}
