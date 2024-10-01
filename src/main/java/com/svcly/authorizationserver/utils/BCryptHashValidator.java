/*
 * (C)2024 - Author: Jaehwan Kim (kkjaehwan@gmail.com)
 * 
 * This file is part of the Svcly Authorization Server project.
 * 
 * This code handles user authentication and authorization services.
 */
package com.svcly.authorizationserver.utils;

import java.util.regex.Pattern;

/**
 * Utility class for validating whether a given string is a valid BCrypt hash. It checks the format
 * of the hash using a regular expression that matches the standard BCrypt pattern.
 */
public class BCryptHashValidator {

  // Regular expression pattern that matches valid BCrypt hash formats
  private static final Pattern BCryptPattern =
      Pattern.compile("^\\$2[ayb]\\$[0-9]{2}\\$[./A-Za-z0-9]{53}$");

  /**
   * Validates if the given string is a valid BCrypt hash.
   *
   * @param candidate The string to be checked.
   * @return {@code true} if the string is a valid BCrypt hash, {@code false} otherwise.
   */
  public static boolean isBCryptHash(String candidate) {
    return candidate != null
        && candidate.length() == 60 // BCrypt hashes have a fixed length of 60 characters
        && BCryptPattern.matcher(candidate).matches(); // Check if it matches the BCrypt pattern
  }
}
