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
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Entity class representing a user in the system, implementing the {@link UserDetails} interface to
 * integrate with Spring Security. This class contains fields such as username, email, and password,
 * along with various security-related attributes like account status and roles.
 */
@Entity
@Data
@Table(name = "accounts")
public class CustomUser implements UserDetails {

  private static final long serialVersionUID = -2022007511148236555L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id; // Unique identifier for each user

  @Column(nullable = false)
  private String username; // Username used for authentication

  @Column(nullable = false, unique = true)
  private String email; // User's email, must be unique

  @Column(nullable = false)
  private String password; // Encrypted password for authentication

  private boolean enabled = true; // Indicates whether the account is active
  private boolean accountNonExpired = true; // Indicates if the account has expired
  private boolean credentialsNonExpired = true; // Indicates if the credentials (password) are valid
  private boolean accountNonLocked = true; // Indicates if the account is locked

  /**
   * Returns the authorities granted to the user. This is where roles are mapped to {@link
   * GrantedAuthority} objects.
   *
   * @return A collection of granted authorities, typically based on the user's roles.
   */
  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return this.getRoles().stream()
        .map(
            role ->
                new SimpleGrantedAuthority(
                    role.getName())) // Map each role to a SimpleGrantedAuthority
        .map(
            grantedAuthority ->
                (GrantedAuthority) grantedAuthority) // Explicit casting to GrantedAuthority
        .toList();
  }

  /**
   * Defines a many-to-many relationship between users and roles. The roles are eagerly fetched to
   * ensure they are always loaded when the user is loaded.
   */
  @ManyToMany(fetch = FetchType.EAGER)
  @JoinTable(
      name = "account_roles",
      joinColumns = @JoinColumn(name = "user_id"),
      inverseJoinColumns = @JoinColumn(name = "role_id"))
  private Set<Role> roles = new HashSet<>(); // A set of roles associated with the user
}
