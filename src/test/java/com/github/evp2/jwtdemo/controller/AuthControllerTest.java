package com.github.evp2.jwtdemo.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.github.evp2.jwtdemo.config.DataSourceConfig;
import com.github.evp2.jwtdemo.config.SecurityConfig;
import com.github.evp2.jwtdemo.service.RegisterService;
import com.github.evp2.jwtdemo.service.TokenService;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@WebMvcTest({AuthController.class})
@Import({DataSourceConfig.class, SecurityConfig.class, RegisterService.class, TokenService.class})
class AuthControllerTest {

  @Autowired MockMvc mvc;

  @Test
  void shouldReturnJwtWithValidUserCredentials() throws Exception {
    this.mvc
        .perform(post("/token").with(httpBasic("evp2", "{noop}password")))
        .andExpect(status().isOk());
  }

  @Test
  void shouldReturnUnauthorizedWithInValidUserCredentials() throws Exception {
    this.mvc
        .perform(post("/token").with(httpBasic("admin", "admin")))
        .andExpect(status().isUnauthorized());
  }

  @Test
  @Order(value = 1)
  void shouldReturnTokenAfterValidRegister() throws Exception {
    this.mvc
        .perform(
            post("/register")
                .contentType("application/json")
                .content(
                    """
              {
                "username": "test",
                "email": "test@email.com",
                "password": "password"
              }
            """))
        .andExpect(status().isOk());
    MvcResult result =
        this.mvc
            .perform(
                post("/login")
                    .contentType("application/json")
                    .content(
                        """
                  {
                    "username": "test",
                    "password": "password"
                  }
                """))
            .andReturn();
    String jwt = result.getResponse().getContentAsString();
    assertThat(jwt).isNotEmpty();
    MvcResult response =
        this.mvc
            .perform(get("/").header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt))
            .andExpect(status().isOk())
            .andReturn();

    assertEquals("Hello, test", response.getResponse().getContentAsString());
    result =
        this.mvc
            .perform(get("/authorizations").header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt))
            .andExpect(status().isOk())
            .andReturn();
    assertEquals("User authorizations: [SCOPE_READ]", result.getResponse().getContentAsString());
  }

  @Test
  @Order(value = 2)
  public void shouldReturnErrorIfUserAlreadyExists() throws Exception {
    this.mvc
        .perform(
            post("/register")
                .contentType("application/json")
                .content(
                    """
              {
                "username": "test",
                "email": "test@email.com",
                "password": "password"
              }
            """))
        .andExpect(status().is4xxClientError());
  }

  @Test
  void shouldReturnTokenWithUsernameAndPassword() throws Exception {
    this.mvc
        .perform(
            post("/login")
                .contentType("application/json")
                .content(
                    """
                  {
                    "username": "evp2",
                    "password": "password"
                  }
                """))
        .andExpect(status().isOk());
  }

  @Test
  void shouldReturnUnauthorizedWithInvalidUsernameAndPassword() throws Exception {
    this.mvc
        .perform(
            post("/login")
                .contentType("application/json")
                .content(
                    """
                  {
                    "username": "admin",
                    "password": "admin"
                  }
                """))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void shouldReturnUnauthorizedWithNoJwt() throws Exception {
    this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
  }

  @Test
  void shouldReturnUnauthorizedWithInvalidJwt() throws Exception {
    this.mvc
        .perform(
            get("/")
                .header(HttpHeaders.AUTHORIZATION, "Bearer ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void shouldReturnWelcomeMessageWithValidJwt() throws Exception {
    MvcResult result =
        this.mvc.perform(post("/token").with(httpBasic("evp2", "{noop}password"))).andReturn();
    String jwt = result.getResponse().getContentAsString();
    assertThat(jwt).isNotEmpty();

    MvcResult response =
        this.mvc
            .perform(get("/").header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt))
            .andExpect(status().isOk())
            .andReturn();

    assertEquals("Hello, evp2", response.getResponse().getContentAsString());
  }
}
