package com.github.evp2.jwtdemo.controller;

import com.github.evp2.jwtdemo.model.LoginRequest;
import com.github.evp2.jwtdemo.model.PasswordResetRequest;
import com.github.evp2.jwtdemo.model.RegisterRequest;
import com.github.evp2.jwtdemo.service.JwtTokenService;
import com.github.evp2.jwtdemo.service.UserDetailsService;
import jakarta.servlet.http.HttpServletResponse;
import java.security.Principal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuthController {
  private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);
  private final AuthenticationManager authenticationManager;
  private final UserDetailsService userDetailsService;
  private final JwtTokenService JwtTokenService;
  private final PasswordEncoder passwordEncoder;

  public AuthController(
      AuthenticationManager authenticationManager,
      UserDetailsService userDetailsService,
      JwtTokenService JwtTokenService,
      PasswordEncoder passwordEncoder) {
    this.authenticationManager = authenticationManager;
    this.userDetailsService = userDetailsService;
    this.JwtTokenService = JwtTokenService;
    this.passwordEncoder = passwordEncoder;
  }

  @GetMapping("/")
  public String home(Principal principal) {
    return "Hello, " + principal.getName();
  }

  @PreAuthorize("hasAuthority('SCOPE_READ')")
  @GetMapping("/authorizations")
  public String authorizations(Authentication authentication) {
    return String.format("User authorizations: %s", authentication.getAuthorities());
  }

  @PostMapping("/token")
  public String token(Authentication authentication) {
    LOG.info("Token requested for user: '{}'", authentication.getName());
    String token = JwtTokenService.generateToken(authentication);
    LOG.debug("Token granted for: {}", authentication.getName());
    return token;
  }

  @PostMapping("/login")
  public String login(@RequestBody LoginRequest loginRequest) {
    LOG.info("Login attempt for user: '{}'", loginRequest.username());
    Authentication authentication =
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                loginRequest.username(), passwordEncoder.encode(loginRequest.password())));
    String token = JwtTokenService.generateToken(authentication);
    LOG.debug("User {} authenticated successfully. JWT: {}", authentication.getName(), token);
    return token;
  }

  @PostMapping("/register")
  public String register(
      @RequestBody RegisterRequest registerRequest, HttpServletResponse response) {
    LOG.info("Register attempt for user: '{}'", registerRequest.username());
    try {
      userDetailsService.registerUser(registerRequest);
    } catch (Exception e) {
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      return "Error: " + e.getMessage();
    }
    LOG.debug("User {} registered successfully", registerRequest.username());
    return String.format("Welcome, %s", registerRequest.username());
  }

  @PreAuthorize("hasAuthority('SCOPE_WRITE')")
  @DeleteMapping("/delete/{username}")
  public String deleteUser(@PathVariable String username, HttpServletResponse response) {
    LOG.info("Delete attempt for user: '{}'", username);
    try {
      userDetailsService.deleteUser(username);
    } catch (Exception e) {
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      return "Error: " + e.getMessage();
    }
    LOG.debug("User {} deleted successfully", username);
    return String.format("User %s deleted successfully", username);
  }

  @PreAuthorize(
      "hasAuthority('SCOPE_WRITE') || authentication.name == #passwordResetRequest.username")
  @PostMapping("/password/reset")
  public String resetPassword(
      @RequestBody PasswordResetRequest passwordResetRequest, HttpServletResponse response) {
    LOG.info("Password reset attempt for user: '{}'", passwordResetRequest.username());
    try {
      userDetailsService.resetPassword(passwordResetRequest);
    } catch (Exception e) {
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      return "Error: " + e.getMessage();
    }
    LOG.debug("Password for user {} reset successfully", passwordResetRequest.username());
    return String.format(
        "Password for user %s reset successfully", passwordResetRequest.username());
  }
}
