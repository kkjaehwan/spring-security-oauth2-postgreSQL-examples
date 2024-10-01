/*
 * (C)2024 - Author: Jaehwan Kim (kkjaehwan@gmail.com)
 * 
 * This file is part of the Svcly Authorization Server project.
 * 
 * This code handles user authentication and authorization services.
 */
package com.svcly.authorizationserver.utils;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;

/**
 * Utility class for mapping OAuth2-related configuration values such as client authentication
 * methods, authorization grant types, and scopes. This class provides methods to map strings from
 * configuration files into appropriate OAuth2 objects used by Spring Security.
 */
public class OAuth2Utils {

  /**
   * Maps a list of string-based client authentication methods to a set of {@link
   * ClientAuthenticationMethod} objects.
   *
   * @param methods The list of client authentication methods in string format.
   * @return A set of {@link ClientAuthenticationMethod} objects.
   * @throws IllegalArgumentException If an unknown authentication method is provided.
   */
  public static Set<ClientAuthenticationMethod> mapClientAuthenticationMethods(
      List<String> methods) {
    Set<ClientAuthenticationMethod> mappedMethods = new HashSet<>();
    for (String method : methods) {
      switch (method) {
        case "client_secret_basic":
          mappedMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
          break;
        case "client_secret_post":
          mappedMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_POST);
          break;
        case "client_secret_jwt":
          mappedMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
          break;
        case "private_key_jwt":
          mappedMethods.add(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
          break;
        case "none":
          mappedMethods.add(ClientAuthenticationMethod.NONE);
          break;
        case "tls_client_auth":
          mappedMethods.add(ClientAuthenticationMethod.TLS_CLIENT_AUTH);
          break;
        case "self_signed_tls_client_auth":
          mappedMethods.add(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH);
          break;
        default:
          throw new IllegalArgumentException("Unknown client authentication method: " + method);
      }
    }
    return mappedMethods;
  }

  /**
   * Maps a list of string-based authorization grant types to a set of {@link
   * AuthorizationGrantType} objects.
   *
   * @param types The list of authorization grant types in string format.
   * @return A set of {@link AuthorizationGrantType} objects.
   * @throws IllegalArgumentException If an unknown grant type is provided.
   */
  public static Set<AuthorizationGrantType> mapAuthorizationGrantTypes(List<String> types) {
    Set<AuthorizationGrantType> mappedTypes = new HashSet<>();
    for (String type : types) {
      switch (type) {
        case "authorization_code":
          mappedTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
          break;
        case "refresh_token":
          mappedTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
          break;
        case "client_credentials":
          mappedTypes.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
          break;
        case "urn:ietf:params:oauth:grant-type:jwt-bearer":
          mappedTypes.add(AuthorizationGrantType.JWT_BEARER);
          break;
        case "urn:ietf:params:oauth:grant-type:device_code":
          mappedTypes.add(AuthorizationGrantType.DEVICE_CODE);
          break;
        case "urn:ietf:params:oauth:grant-type:token-exchange":
          mappedTypes.add(AuthorizationGrantType.TOKEN_EXCHANGE);
          break;
        default:
          throw new IllegalArgumentException("Unknown authorization grant type: " + type);
      }
    }
    return mappedTypes;
  }

  /**
   * Maps a list of string-based scopes to a set of scope strings used in OAuth2. This includes
   * standard OIDC scopes and custom scopes like "read" and "write".
   *
   * @param scopes The list of scopes in string format.
   * @return A set of scopes as strings.
   * @throws IllegalArgumentException If an unknown scope is provided.
   */
  public static Set<String> mapScopes(List<String> scopes) {
    Set<String> mappedScopes = new HashSet<>();
    for (String scope : scopes) {
      switch (scope) {
        case OidcScopes.OPENID:
          mappedScopes.add(OidcScopes.OPENID);
          break;
        case OidcScopes.PROFILE:
          mappedScopes.add(OidcScopes.PROFILE);
          break;
        case OidcScopes.EMAIL:
          mappedScopes.add(OidcScopes.EMAIL);
          break;
        case OidcScopes.ADDRESS:
          mappedScopes.add(OidcScopes.ADDRESS);
          break;
        case OidcScopes.PHONE:
          mappedScopes.add(OidcScopes.PHONE);
          break;
        case "read":
          mappedScopes.add("read");
          break;
        case "write":
          mappedScopes.add("write");
          break;
        default:
          throw new IllegalArgumentException("Unknown scope: " + scope);
      }
    }
    return mappedScopes;
  }
}
