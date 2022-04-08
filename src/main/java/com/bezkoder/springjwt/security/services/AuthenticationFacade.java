package com.bezkoder.springjwt.security.services;


public interface AuthenticationFacade {

    void setAuthentication(String username, String password);

    UserDetailsImpl getAuthentication();

}
