package com.github.evp2.jwtdemo.config;

import static org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType.H2;
import static org.springframework.security.config.Customizer.withDefaults;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import javax.crypto.spec.SecretKeySpec;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Value("${jwt.key}")
  private String jwtKey;

  @Bean
  public AuthenticationManager authenticationManager(UserDetailsManager users) {
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(users);
    return new ProviderManager(authProvider);
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http.csrf(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests(
            auth ->
                auth.requestMatchers(new AntPathRequestMatcher("/login"))
                    .permitAll()
                    .requestMatchers(new AntPathRequestMatcher("/register"))
                    .permitAll()
                    .anyRequest()
                    .hasAuthority("SCOPE_READ"))
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
        .exceptionHandling(
            (ex) -> {
              ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
              ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
            })
        .build();
  }

  /*
   * Allow the token endpoint to use basic auth and everything else uses the default filter chain
   */
  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain tokenSecurityFilterChain(HttpSecurity http) throws Exception {
    return http.securityMatcher(new AntPathRequestMatcher("/token"))
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .csrf(AbstractHttpConfigurer::disable)
        .exceptionHandling(
            (ex) -> {
              ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
              ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
            })
        .httpBasic(withDefaults())
        .build();
  }

  @Profile({"dev"})
  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain h2ConsoleSecurityFilterChain(HttpSecurity http) throws Exception {
    return http.securityMatcher(new AntPathRequestMatcher("/h2-console/**"))
        .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
        .csrf(csrf -> csrf.ignoringRequestMatchers(new AntPathRequestMatcher("/h2-console/**")))
        .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))
        .build();
  }

  @Bean
  public JwtEncoder jwtEncoder() {
    return new NimbusJwtEncoder(new ImmutableSecret<>(jwtKey.getBytes()));
  }

  @Bean
  public JwtDecoder jwtDecoder() {
    byte[] bytes = jwtKey.getBytes();
    SecretKeySpec originalKey = new SecretKeySpec(bytes, 0, bytes.length, "RSA");
    return NimbusJwtDecoder.withSecretKey(originalKey).macAlgorithm(MacAlgorithm.HS512).build();
  }

  @Bean
  public DataSource dataSource() {
    return new EmbeddedDatabaseBuilder()
        .setType(H2)
        .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
        .build();
  }

  @Bean
  public DataSource userDetailsDataSource() {
    return new EmbeddedDatabaseBuilder()
        .setType(H2)
        .addScript("classpath:user_details.ddl")
        .build();
  }

  @Bean
  public UserDetailsManager users(DataSource dataSource, PasswordEncoder passwordEncoder) {
    UserDetails user =
        User.withUsername("evp2")
            .password(passwordEncoder.encode("{noop}password"))
            .authorities("READ", "ROLE_ADMIN")
            .build();
    JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
    users.createUser(user);
    return users;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
  }
}
