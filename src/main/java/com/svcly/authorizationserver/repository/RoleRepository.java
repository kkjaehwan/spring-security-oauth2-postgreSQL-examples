/*
 * (C)2024 - Author: Jaehwan Kim (kkjaehwan@gmail.com)
 * 
 * This file is part of the Svcly Authorization Server project.
 * 
 * This code handles user authentication and authorization services.
 */
package com.svcly.authorizationserver.repository;

import com.svcly.authorizationserver.entity.Role;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Repository interface for managing {@link Role} entities. Extends the {@link JpaRepository}
 * interface to provide CRUD operations for the Role entity, such as finding, saving, and deleting
 * roles. This interface also defines a method for finding roles by their name.
 */
public interface RoleRepository extends JpaRepository<Role, Long> {

  /**
   * Finds a role by its name.
   *
   * @param name The name of the role to find (e.g., ROLE_USER, ROLE_ADMIN).
   * @return An {@link Optional} containing the role if found, or empty if not found.
   */
  Optional<Role> findByName(String name); // Query method to find a role by its name
}
