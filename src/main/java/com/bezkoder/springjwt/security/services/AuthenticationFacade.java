package com.bezkoder.springjwt.security.services;


import org.springframework.security.core.userdetails.UserDetails;

public interface AuthenticationFacade {

    void setAuthentication(String username, String password);

    UserDetails getAuthentication();

}
