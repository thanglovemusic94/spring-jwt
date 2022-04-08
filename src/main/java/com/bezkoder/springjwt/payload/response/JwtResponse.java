package com.bezkoder.springjwt.payload.response;

public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private String refreshToken;

    public JwtResponse(String token) {
        this.token = token;
    }

    public JwtResponse(String token, String refreshToken) {
        this.token = token;
        this.refreshToken = refreshToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

}
