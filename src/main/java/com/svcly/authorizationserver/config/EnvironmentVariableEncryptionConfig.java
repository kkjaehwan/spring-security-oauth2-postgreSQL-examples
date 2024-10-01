/*
 * (C)2024 - Author: Jaehwan Kim (kkjaehwan@gmail.com)
 * 
 * This file is part of the Svcly Authorization Server project.
 * 
 * This code handles user authentication and authorization services.
 */
package com.svcly.authorizationserver.config;

import com.svcly.authorizationserver.utils.BCryptHashValidator;
import jakarta.annotation.PostConstruct;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

/**
 * This configuration class handles the encryption of sensitive variables such as client secrets in
 * the application's YAML file. It checks if these variables are already encrypted and, if not,
 * encrypts them using BCrypt, then updates the YAML file with the encrypted values.
 */
@Configuration
@Slf4j
public class EnvironmentVariableEncryptionConfig {

  // Path to the application's YAML configuration file
  private static final String APPLICATION_YAML_PATH = "src/main/resources/application.yml";

  // List of paths in the YAML file that point to sensitive values needing encryption
  private static final List<String> SECRET_PATHS =
      List.of(
          "spring.security.oauth2.authorizationserver.client.oidc-client.registration.client-secret");

  private final Environment environment;

  /**
   * Constructor that initializes the Environment object used to retrieve configuration properties.
   *
   * @param environment Spring's Environment object to access properties
   */
  public EnvironmentVariableEncryptionConfig(Environment environment) {
    this.environment = environment;
  }

  /**
   * This method is called after the bean initialization to ensure that any sensitive data in the
   * YAML file is encrypted. It iterates over the predefined secret paths, checks if they are
   * encrypted, and if not, encrypts them and updates the YAML file.
   */
  @PostConstruct
  public void encryptSecretsIfNecessary() {
    PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    Map<String, String> secretsToEncrypt = new HashMap<>();

    // Iterate through the list of secret paths
    for (String path : SECRET_PATHS) {
      // Retrieve the current value of the secret from the environment
      String secretValue = environment.getProperty(path, "defaultSecret");

      // Check if the secret is already encrypted using BCrypt
      if (!BCryptHashValidator.isBCryptHash(secretValue)) {
        // Encrypt the secret if not already encrypted
        String encryptedSecret = passwordEncoder.encode(secretValue);
        log.debug(
            "Secret at path '{}' is not encoded. Original value: '{}', Encrypted value: '{}'",
            path,
            secretValue,
            encryptedSecret);
        secretsToEncrypt.put(path, encryptedSecret);
      }
    }

    // If there are any secrets to encrypt, update the YAML file
    if (!secretsToEncrypt.isEmpty()) {
      try {
        updateYamlWithEncryptedSecrets(secretsToEncrypt);
        log.info("Successfully updated client secrets in YAML file.");
      } catch (IOException e) {
        log.error("Error occurred while updating client secrets in YAML file", e);
      }
    }
  }

  /**
   * Updates the YAML configuration file with the encrypted secrets.
   *
   * @param secretsToEncrypt A map containing paths and their corresponding encrypted values
   * @throws IOException If there is an issue reading or writing to the YAML file
   */
  private void updateYamlWithEncryptedSecrets(Map<String, String> secretsToEncrypt)
      throws IOException {
    Yaml yaml = new Yaml(createDumperOptions());
    Map<String, Object> yamlData;

    // Read the existing YAML file into a map
    try (FileInputStream inputStream = new FileInputStream(APPLICATION_YAML_PATH)) {
      yamlData = yaml.load(inputStream);
    }

    // Update the secrets in the YAML data structure
    secretsToEncrypt.forEach(
        (path, encryptedSecret) -> {
          try {
            applySecretToYamlData(yamlData, path, encryptedSecret);
          } catch (IllegalArgumentException e) {
            log.warn("Failed to update secret at path '{}': {}", path, e.getMessage());
          }
        });

    // Write the updated YAML data back to the file
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(APPLICATION_YAML_PATH))) {
      yaml.dump(yamlData, writer);
    }
  }

  /**
   * Configures the YAML dumper options for better readability (block style with 2-space
   * indentation).
   *
   * @return DumperOptions configured for block-style YAML
   */
  private DumperOptions createDumperOptions() {
    DumperOptions options = new DumperOptions();
    options.setDefaultFlowStyle(
        DumperOptions.FlowStyle.BLOCK); // Ensure block style for readability
    options.setIndent(2); // Set the indentation level
    return options;
  }

  /**
   * Applies the encrypted secret to the YAML data structure. This method traverses the path
   * hierarchy in the map and replaces the appropriate value with the encrypted secret.
   *
   * @param yamlData The YAML data structure
   * @param path The path in dot notation where the secret should be stored
   * @param newSecret The encrypted secret to store
   */
  @SuppressWarnings("unchecked")
  private void applySecretToYamlData(Map<String, Object> yamlData, String path, String newSecret) {
    String[] keys = path.split("\\.");
    Map<String, Object> currentMap = yamlData;

    // Traverse the YAML data structure according to the path
    for (int i = 0; i < keys.length - 1; i++) {
      Object next = currentMap.get(keys[i]);
      if (next instanceof Map) {
        currentMap = (Map<String, Object>) next;
      } else {
        // Create a new map if one does not exist for the given key
        Map<String, Object> newMap = new HashMap<>();
        currentMap.put(keys[i], newMap);
        currentMap = newMap;
      }
    }

    // Set the encrypted secret at the final key
    currentMap.put(keys[keys.length - 1], newSecret);
  }
}
