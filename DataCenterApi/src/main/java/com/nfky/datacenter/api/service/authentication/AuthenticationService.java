package com.nfky.datacenter.api.service.authentication;

import com.nfky.datacenter.api.dao.app.AppInfoRepository;
import com.nfky.datacenter.api.entity.app.AppInfo;
import com.nfky.datacenter.common.base.BaseService;

import com.nfky.datacenter.security.util.JWTTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.asList;

/**
 * Created by TYZ016 on 2017/6/12.
 */
@Service
public class AuthenticationService extends BaseService<AppInfoRepository, AppInfo, Integer> {
    @Autowired
    private AppInfoRepository appInfoRep;

    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.expiration}")
    private long expiration;


    /**
     * app认证
     *
     * @param appId app标识
     * @param appKey app密钥
     * @return
     * @throws Exception
     */
    public String authenticate(String appId, String appKey) throws Exception {
        AppInfo appInfo = appInfoRep.findByAppId(appId);

        if (appInfo == null) {
            throw new Exception("can not find app info");
        }

        if (!appKey.equals(appInfo.getAppKey())) {
            throw new Exception("authentication failed");
        }

        Map<String, Object> claims = new HashMap<>();
        claims.put("user_name", appInfo.getAppId());
        claims.put("created", new Date());

        return JWTTokenUtil.produceToken(claims, expiration, secret);
    }

}
