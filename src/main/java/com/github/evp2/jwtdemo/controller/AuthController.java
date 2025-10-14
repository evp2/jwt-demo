package com.github.evp2.jwtdemo.controller;

import com.github.evp2.jwtdemo.model.LoginRequest;
import com.github.evp2.jwtdemo.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class AuthController {

  private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);

  private final AuthenticationManager authenticationManager;
  private final TokenService tokenService;

  public AuthController(AuthenticationManager authenticationManager, TokenService tokenService) {
    this.authenticationManager = authenticationManager;
    this.tokenService = tokenService;
  }

  @GetMapping("/")
  public String home(Principal principal) {
    return "Hello, " + principal.getName();
  }

  @PreAuthorize("hasAuthority('SCOPE_read')")
  @GetMapping("/authorizations")
  public String authorizations() {
    return "User has 'read' scope.";
  }

  @PostMapping("/token")
  public String token(Authentication authentication) {
    LOG.info("Token requested for user: '{}'", authentication.getName());
    String token = tokenService.generateToken(authentication);
    LOG.debug("Token granted: {}", token);
    return token;
  }

  @PostMapping("/login")
  public String login(@RequestBody LoginRequest loginRequest) {
    LOG.info("Login attempt for user: '{}'", loginRequest.username());
    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            loginRequest.username(),
            loginRequest.password()
        )
    );
    LOG.debug("User {} authenticated successfully", authentication.getName());
    String token = tokenService.generateToken(authentication);
    LOG.debug("Login JWT Token: {}", token);
    return token;
  }

}