package com.nfky.datacenter.security.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by lyr on 2017/6/13.
 */
public class JWTAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private String tokenHeader;

    private String tokenPrefix;

    private String tokenParam;

    public JWTAuthenticationFilter(String defaultFilterProcessesUrl, String tokenHeader, String tokenPrefix, String tokenParam) {
        super(defaultFilterProcessesUrl);
        this.tokenHeader = tokenHeader;
        this.tokenPrefix = tokenPrefix;
        this.tokenParam = tokenParam;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        String authHeader = request.getHeader(this.tokenHeader);
        boolean isTokenParam = false;

        if (StringUtils.isEmpty(authHeader)) {
            authHeader = request.getParameter(tokenParam);

            if (!StringUtils.isEmpty(authHeader)) {
                isTokenParam = true;
            }
        }

        String authToken = "";

        if (authHeader != null) {
            authToken = isTokenParam ? authHeader : authHeader.substring(tokenPrefix.length());
        }

        JWTAuthentication authentication = new JWTAuthentication(authToken, "", "");

        return getAuthenticationManager().authenticate(authentication);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        chain.doFilter(request, response);
    }
}
