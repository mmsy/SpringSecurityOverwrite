package com.nfky.datacenter.security.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Created by lyr on 2017/6/13.
 */
public class JWTAuthentication extends UsernamePasswordAuthenticationToken {

    private String token;

    public JWTAuthentication(String token, String principal, String credentials) {
        super(principal, credentials);
        this.token = token;
    }

    public String getToken() {
        return token;
    }
}
