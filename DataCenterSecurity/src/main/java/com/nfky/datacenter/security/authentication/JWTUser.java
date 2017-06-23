package com.nfky.datacenter.security.authentication;

import org.springframework.security.core.userdetails.UserDetails;

/**
 * Created by lyr on 2017/6/13.
 */
public interface JWTUser extends UserDetails {

    long getLastModifyTime();

}
