package com.github.evp2.jwtdemo;

import com.github.evp2.jwtdemo.config.RsaKeyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeyProperties.class)
public class JwtDemoApplication {

  public static void main(String[] args) {
    SpringApplication.run(JwtDemoApplication.class, args);
  }

}
