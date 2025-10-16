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
public class RegisterService {
  private static final Logger LOG = LoggerFactory.getLogger(RegisterService.class);
  private final UserDetailsManager userDetailsManager;
  private final DataSource personDataSource;

  public RegisterService(UserDetailsManager userDetailsManager, DataSource personDataSource) {
    this.userDetailsManager = userDetailsManager;
    this.personDataSource = personDataSource;
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
    personDataSource
        .getConnection()
        .prepareStatement(
            "INSERT INTO user_details (username, email) VALUES ('%s', '%s')"
                .formatted(registerRequest.username(), registerRequest.email()))
        .executeUpdate();
  }
}
