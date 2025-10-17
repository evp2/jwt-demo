package com.github.evp2.jwtdemo.model;

public record PasswordResetRequest(String username, String password, String newPassword) {}
