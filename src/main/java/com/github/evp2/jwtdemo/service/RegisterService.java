package com.github.evp2.jwtdemo.service;

import com.github.evp2.jwtdemo.model.RegisterRequest;
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

  public RegisterService(UserDetailsManager userDetailsManager) {
    this.userDetailsManager = userDetailsManager;
  }

  public void registerUser(RegisterRequest registerRequest) {
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
  }
}
