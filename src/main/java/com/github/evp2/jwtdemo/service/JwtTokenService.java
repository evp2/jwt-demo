package com.github.evp2.jwtdemo.service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

@Service
public class JwtTokenService {

  private final JwtEncoder encoder;
  private final UserDetailsManager userDetailsManager;

  public JwtTokenService(JwtEncoder encoder, UserDetailsManager userDetailsManager) {
    this.encoder = encoder;
    this.userDetailsManager = userDetailsManager;
  }

  public String generateToken(Authentication authentication) {
    Instant now = Instant.now();
    if (!userDetailsManager.userExists(authentication.getName())) {
      throw new RuntimeException("User does not exist");
    }
    String scope =
        authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .filter(authority -> !authority.startsWith("ROLE"))
            .collect(Collectors.joining(" "));
    JwtClaimsSet claims =
        JwtClaimsSet.builder()
            .issuer("self")
            .issuedAt(now)
            .expiresAt(now.plus(24, ChronoUnit.HOURS))
            .subject(authentication.getName())
            .claim("scope", scope)
            .build();
    JwtEncoderParameters encoderParameters =
        JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS512).build(), claims);
    return this.encoder.encode(encoderParameters).getTokenValue();
  }
}
