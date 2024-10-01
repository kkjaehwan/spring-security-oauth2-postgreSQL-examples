/*
 * (C)2024 - Author: Jaehwan Kim (kkjaehwan@gmail.com)
 * 
 * This file is part of the Svcly Authorization Server project.
 * 
 * This code handles user authentication and authorization services.
 */
package com.svcly.authorizationserver.repository;

import com.svcly.authorizationserver.entity.CustomUser;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Repository interface for managing {@link CustomUser} entities. Extends the {@link JpaRepository}
 * interface to provide CRUD operations for the CustomUser entity. This interface also defines
 * methods for finding users by their username and email, which are common lookup operations in
 * authentication processes.
 */
public interface UserRepository extends JpaRepository<CustomUser, Long> {

  /**
   * Finds a user by their username.
   *
   * @param username The username of the user to find.
   * @return The {@link CustomUser} object if found, otherwise null.
   */
  CustomUser findByUsername(String username); // Query method to find a user by their username

  /**
   * Finds a user by their email.
   *
   * @param email The email of the user to find.
   * @return An {@link Optional} containing the user if found, or empty if not found.
   */
  Optional<CustomUser> findByEmail(String email); // Query method to find a user by their email
}
