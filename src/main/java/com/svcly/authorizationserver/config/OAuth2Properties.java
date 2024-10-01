/*
 * (C)2024 - Author: Jaehwan Kim (kkjaehwan@gmail.com)
 * 
 * This file is part of the Svcly Authorization Server project.
 * 
 * This code handles user authentication and authorization services.
 */
package com.svcly.authorizationserver.config;

import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration class that maps OAuth2 client-related properties from the application's YAML or
 * properties file. The prefix used to map these properties is
 * 'spring.security.oauth2.authorizationserver.client.oidc-client'.
 *
 * <p>This class holds all the necessary information about OAuth2 client registration, including
 * client credentials, authentication methods, authorization grant types, and redirect URIs.
 */
@Component
@ConfigurationProperties(prefix = "spring.security.oauth2.authorizationserver.client.oidc-client")
@Data
public class OAuth2Properties {

  // Nested class holding client registration details such as clientId, clientSecret, etc.
  private Registration registration;

  // Flag indicating whether authorization consent is required for the client
  private Boolean requireAuthorizationConsent;

  /**
   * Static inner class to hold registration-specific properties such as clientId, clientSecret,
   * authentication methods, grant types, redirect URIs, post-logout URIs, and scopes.
   */
  @Data
  public static class Registration {
    // Client ID used for OAuth2 client registration
    private String clientId;

    // Client secret used for OAuth2 client authentication
    private String clientSecret;

    // List of authentication methods supported by the client (e.g., client_secret_basic)
    private List<String> clientAuthenticationMethods;

    // List of authorization grant types supported by the client (e.g., authorization_code)
    private List<String> authorizationGrantTypes;

    // List of valid redirect URIs for the client during the authorization process
    private List<String> redirectUris;

    // List of URIs to redirect to after logout
    private List<String> postLogoutRedirectUris;

    // List of OAuth2 scopes requested by the client (e.g., openid, profile)
    private List<String> scopes;
  }
}
