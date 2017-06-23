package com.nfky.datacenter.security.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by lyr on 2017/6/14.
 */
public class JWTAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    public JWTAuthenticationSuccessHandler() {

    }

    @Override
    protected void handle(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

    }
}
