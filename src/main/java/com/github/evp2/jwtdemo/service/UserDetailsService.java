package com.github.evp2.jwtdemo.service;

import com.github.evp2.jwtdemo.model.RegisterRequest;
import java.sql.SQLException;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsService {
  private static final Logger LOG = LoggerFactory.getLogger(UserDetailsService.class);
  private final UserDetailsManager userDetailsManager;
  private final DataSource userDetailsDataSource;

  public UserDetailsService(
      UserDetailsManager userDetailsManager, DataSource userDetailsDataSource) {
    this.userDetailsManager = userDetailsManager;
    this.userDetailsDataSource = userDetailsDataSource;
  }

  public void registerUser(RegisterRequest registerRequest) throws SQLException {
    assert !registerRequest.username().isEmpty()
        && !registerRequest.email().isEmpty()
        && !registerRequest.password().isEmpty();
    if (userDetailsManager.userExists(registerRequest.username())) {
      LOG.warn("User: {} already exists", registerRequest.username());
      throw new RuntimeException("User already exists");
    }
    UserDetails user =
        User.withUsername(registerRequest.username())
            .password("{noop}" + registerRequest.password())
            .authorities("READ", "ROLE_USER")
            .build();
    userDetailsManager.createUser(user);
    userDetailsDataSource
        .getConnection()
        .prepareStatement(
            "INSERT INTO user_details (username, email) VALUES ('%s', '%s')"
                .formatted(registerRequest.username(), registerRequest.email()))
        .executeUpdate();
  }

  public void deleteUser(String username) throws SQLException {
    if (!userDetailsManager.userExists(username)) {
      LOG.warn("User: {} does not exist", username);
      throw new RuntimeException("User does not exist");
    }
    userDetailsManager.deleteUser(username);
    userDetailsDataSource
        .getConnection()
        .prepareStatement("DELETE FROM user_details WHERE username = '%s'".formatted(username))
        .executeUpdate();
  }
}
