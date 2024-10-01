/*
 * (C)2024 - Author: Jaehwan Kim (kkjaehwan@gmail.com)
 * 
 * This file is part of the Svcly Authorization Server project.
 * 
 * This code handles user authentication and authorization services.
 */
package com.svcly.authorizationserver.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

/**
 * Entity class representing a role in the system. A role defines the permissions or access levels
 * assigned to a user, such as ROLE_USER or ROLE_ADMIN. Roles are stored in the 'roles' table and
 * are linked to users through a many-to-many relationship.
 */
@Data
@Entity
@Table(name = "roles")
public class Role {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id; // Unique identifier for each role

  @Column(unique = true, nullable = false)
  private String name; // The name of the role, which must be unique (e.g., ROLE_USER, ROLE_ADMIN)
}
