package com.marouane.customerservice.rest;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
@RestController
public class CustomerRestApi {
@GetMapping("/customer")
public Map<String,Object>customer(Authentication authentication){
  return Map.of("name","Mohame","email","mo@gmail.com",
  "username",authentication.getName(),
          "scope",authentication.getAuthorities());
}
}
