package com.marouane.servicesecurityauth2jwt;

import com.marouane.servicesecurityauth2jwt.secr.RsakeyConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@EnableConfigurationProperties(RsakeyConfig.class)
public class ServiceSecurityAuth2JwtApplication {

    public static void main(String[] args) {

        SpringApplication.run(
                ServiceSecurityAuth2JwtApplication.class, args);
    }
@Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
