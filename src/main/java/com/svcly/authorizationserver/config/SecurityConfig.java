/*
 * (C)2024 - Author: Jaehwan Kim (kkjaehwan@gmail.com)
 * 
 * This file is part of the Svcly Authorization Server project.
 * 
 * This code handles user authentication and authorization services.
 */
package com.svcly.authorizationserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.svcly.authorizationserver.config.OAuth2Properties.Registration;
import com.svcly.authorizationserver.utils.OAuth2Utils;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

/**
 * This class contains the security configuration for both the OAuth2 Authorization Server and the
 * client application. It configures key security features, JWT handling, client registration, and
 * encryption mechanisms for secure communication.
 */
@Configuration
public class SecurityConfig {

  @Autowired private OAuth2Properties oAuth2Properties;

  // List of endpoints that should be accessible without authentication
  private static final List<String> WHITELIST = Arrays.asList("/login", "/users/register");

  /**
   * Configures the security filter chain for the OAuth2 Authorization Server. It applies the
   * default OAuth2 security settings, enabling OpenID Connect (OIDC) support and configuring
   * JWT-based resource server security.
   *
   * @param http The HttpSecurity object to configure security settings.
   * @return The configured SecurityFilterChain for the Authorization Server.
   * @throws Exception If there is an issue with the configuration.
   */
  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
      throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    // Configure OpenID Connect (OIDC) support with default settings
    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());

    return http.exceptionHandling(
            e -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
        .oauth2ResourceServer(
            oauth2ResourceServer ->
                oauth2ResourceServer.jwt(Customizer.withDefaults())) // JWT configuration
        .build();
  }

  /**
   * Configures the security filter chain for the client application. Disables CSRF protection,
   * configures form login, and applies security settings for whitelisted and authenticated routes.
   *
   * @param http The HttpSecurity object to configure security settings.
   * @return The configured SecurityFilterChain for the client application.
   * @throws Exception If there is an issue with the configuration.
   */
  @Bean
  @Order(2)
  public SecurityFilterChain clientAppSecurityFilterChain(HttpSecurity http) throws Exception {
    return http.csrf(AbstractHttpConfigurer::disable) // Disables CSRF protection
        .formLogin(Customizer.withDefaults()) // Enables form login
        .authorizeHttpRequests(
            authorize ->
                authorize
                    .requestMatchers(WHITELIST.toArray(new String[0])) // Whitelisted paths
                    .permitAll()
                    .anyRequest()
                    .authenticated()) // All other requests require authentication
        .build();
  }

  /**
   * Defines the password encoder to be used for encoding client secrets. Uses BCryptPasswordEncoder
   * for secure password hashing.
   *
   * @return A PasswordEncoder bean.
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  /**
   * Configures the repository for registered OAuth2 clients. Retrieves client registration details
   * from properties and builds a RegisteredClient object.
   *
   * @return A RegisteredClientRepository bean containing the client registration details.
   */
  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    // Accessing properties directly from OAuth2Properties
    Registration registration = oAuth2Properties.getRegistration();
    String clientId = registration.getClientId();
    String clientSecret = registration.getClientSecret();
    List<String> clientAuthenticationMethods = registration.getClientAuthenticationMethods();
    List<String> authorizationGrantTypes = registration.getAuthorizationGrantTypes();
    List<String> redirectUris = registration.getRedirectUris();
    List<String> postLogoutRedirectUris = registration.getPostLogoutRedirectUris();
    List<String> scopes = registration.getScopes();
    boolean requireAuthorizationConsent = oAuth2Properties.getRequireAuthorizationConsent();

    // Build a RegisteredClient using the properties
    RegisteredClient.Builder clientBuilder =
        RegisteredClient.withId(clientId)
            .clientId(clientId)
            .clientSecret(clientSecret)
            .clientAuthenticationMethods(
                clientAuthMethods ->
                    clientAuthMethods.addAll(
                        OAuth2Utils.mapClientAuthenticationMethods(clientAuthenticationMethods)))
            .authorizationGrantTypes(
                grantTypes ->
                    grantTypes.addAll(
                        OAuth2Utils.mapAuthorizationGrantTypes(authorizationGrantTypes)))
            .redirectUris(redirectUrisList -> redirectUrisList.addAll(redirectUris))
            .postLogoutRedirectUris(
                postLogoutUrisList -> postLogoutUrisList.addAll(postLogoutRedirectUris))
            .scopes(scopesList -> scopesList.addAll(OAuth2Utils.mapScopes(scopes)))
            .clientSettings(
                ClientSettings.builder()
                    .requireAuthorizationConsent(requireAuthorizationConsent) // Consent requirement
                    .requireProofKey(true) // Proof Key for Code Exchange (PKCE)
                    .build());

    RegisteredClient registeredClient = clientBuilder.build();

    return new InMemoryRegisteredClientRepository(registeredClient);
  }

  /**
   * Configures the settings for the OAuth2 Authorization Server.
   *
   * @return AuthorizationServerSettings bean with default settings.
   */
  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }

  /**
   * Configures the client settings for OAuth2 clients.
   *
   * @return ClientSettings bean with proof key and consent settings enabled.
   */
  @Bean
  public ClientSettings clientSettings() {
    return ClientSettings.builder().requireAuthorizationConsent(true).requireProofKey(true).build();
  }

  /**
   * Configures the JWT decoder for decoding JWT tokens issued by the Authorization Server.
   *
   * @param jwkSource The JWKSource that contains the RSA key used for signing JWTs.
   * @return JwtDecoder bean.
   */
  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  /**
   * Generates an RSA key pair and wraps it into a JWKSource used for signing JWTs.
   *
   * @return JWKSource bean containing the RSA keys.
   */
  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    RSAKey rsaKey = generateRsa();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
  }

  /**
   * Generates a new RSA key pair used for JWT signing.
   *
   * @return An RSAKey object containing the public and private keys.
   */
  public static RSAKey generateRsa() {
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    return new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString()) // Generates a unique key ID
        .build();
  }

  /**
   * Helper method that generates an RSA key pair with a key size of 2048 bits.
   *
   * @return KeyPair object containing the RSA key pair.
   */
  static KeyPair generateRsaKey() {
    KeyPair keyPair;
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      keyPair = keyPairGenerator.generateKeyPair();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
    return keyPair;
  }
}
