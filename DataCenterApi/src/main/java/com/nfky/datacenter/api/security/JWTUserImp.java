package com.nfky.datacenter.api.security;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Date;

/**
 * Created by lyr on 2017/6/12.
 */
public class JWTUserImp implements com.nfky.datacenter.security.authentication.JWTUser {
    private final String appId;
    private final String appKey;
    private final Collection<? extends GrantedAuthority> authorities;
    private final Date lastModifyTime;

    public JWTUserImp(
            String appId,
            String appKey,
            Collection<? extends GrantedAuthority> authorities,
            Date lastModifyTime) {
        this.appId = appId;
        this.appKey = appKey;
        this.authorities = authorities;
        this.lastModifyTime = lastModifyTime;
    }

    //返回分配给用户的角色列表
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return appKey;
    }

    @Override
    public String getUsername() {
        return appId;
    }

    // 账户是否未过期
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 账户是否未锁定
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 密码是否未过期
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 账户是否激活
    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public long getLastModifyTime() {
        if (lastModifyTime != null) {
            return 0;
        }
        return lastModifyTime.getTime();
    }
}
