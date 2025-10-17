package com.github.evp2.jwtdemo.service;

import com.github.evp2.jwtdemo.model.PasswordResetRequest;
import com.github.evp2.jwtdemo.model.RegisterRequest;
import java.sql.SQLException;
import java.util.regex.Pattern;
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
    Pattern validEmail =
        Pattern.compile(
            "(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])");
    assert !registerRequest.username().isEmpty()
        && !registerRequest.password().isEmpty()
        && !registerRequest.email().isEmpty()
        && validEmail.matcher(registerRequest.email()).matches();
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

  public void resetPassword(PasswordResetRequest passwordResetRequest) {
    if (!userDetailsManager.userExists(passwordResetRequest.username())) {
      LOG.warn("User: {} does not exist", passwordResetRequest.username());
      throw new RuntimeException("User does not exist");
    }
    userDetailsManager.changePassword(
        passwordResetRequest.password(), "{noop}" + passwordResetRequest.newPassword());
  }
}
