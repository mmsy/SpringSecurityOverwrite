package com.nfky.datacenter.api.security;

import java.io.Serializable;

public class  JwtAuthenticationRequest implements Serializable {

    private static final long serialVersionUID = -8445943548965154778L;

    private String appId;
    private String AppKey;

    public JwtAuthenticationRequest() {
        super();
    }

    public JwtAuthenticationRequest(String appId, String AppKey) {
        this.setAppId(appId);
        this.setAppKey(AppKey);
    }

    public String getAppId() {
        return this.appId;
    }

    public void setAppId(String AppId) {
        this.appId = AppId;
    }

    public String getAppKey() {
        return this.AppKey;
    }

    public void setAppKey(String AppKey) {
        this.AppKey = AppKey;
    }
}
