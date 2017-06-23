package com.nfky.datacenter.security.authentication;

import com.nfky.datacenter.security.util.JWTTokenUtil;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Created by lyr on 2017/6/13.
 */
public class JWTAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    private UserDetailsService userService;
    private String secret;
    private UserCache userCache = new NullUserCache();

    public JWTAuthenticationProvider(UserDetailsService userService, String secret) {
        this.userService = userService;
        this.secret = secret;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JWTAuthentication.class.isAssignableFrom(authentication);
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication,
                messages.getMessage(
                        "AbstractUserDetailsAuthenticationProvider.onlySupports",
                        "Only UsernamePasswordAuthenticationToken is supported"));

        // Determine username
        String username = "NONE_PROVIDED";

        JWTAuthentication auth = (JWTAuthentication) authentication;

        if (!StringUtils.isEmpty(auth.getToken())) {
            username = JWTTokenUtil.getUserNameFromToken(auth.getToken(), secret);
        }

        boolean cacheWasUsed = true;
        UserDetails user = this.userCache.getUserFromCache(username);

        if (user == null) {
            cacheWasUsed = false;

            try {
                user = retrieveUser(username,
                        (UsernamePasswordAuthenticationToken) authentication);
            } catch (UsernameNotFoundException notFound) {
                logger.debug("User '" + username + "' not found");

                if (hideUserNotFoundExceptions) {
                    throw new BadCredentialsException(messages.getMessage(
                            "AbstractUserDetailsAuthenticationProvider.badCredentials",
                            "Bad credentials"));
                } else {
                    throw notFound;
                }
            }

            Assert.notNull(user,
                    "retrieveUser returned null - a violation of the interface contract");
        }

        if (!validateToken(auth.getToken(), (JWTUser) user)) {
            throw new BadCredentialsException(messages.getMessage(
                    "AbstractUserDetailsAuthenticationProvider.badCredentials",
                    "Bad credentials"));
        }

        if (!cacheWasUsed) {
            this.userCache.putUserInCache(user);
        }

        Object principalToReturn = user.getUsername();

        Authentication authResult =  createSuccessAuthentication(principalToReturn, authentication, user);
        SecurityContextHolder.getContext().setAuthentication(authResult);
        return authResult;
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        JWTUser user = (JWTUser) userService.loadUserByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException("user not find");
        }

        return user;
    }

    private boolean validateToken(String token, JWTUser user) {
        if (JWTTokenUtil.isTokenExpired(token, secret)) {
            return false;
        }
        if (JWTTokenUtil.getCreatedTimeFromToken(token, secret) <= user.getLastModifyTime()) {
            return false;
        }
        return true;
    }
}
