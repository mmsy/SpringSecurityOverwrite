package com.nfky.datacenter.api.controller.authentication;

import com.nfky.datacenter.api.security.JwtAuthenticationRequest;
import com.nfky.datacenter.api.security.JwtAuthenticationResponse;
import com.nfky.datacenter.api.service.authentication.AuthenticationService;
import com.nfky.datacenter.common.base.BaseController;
import com.nfky.datacenter.common.base.ResponseData;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;


/**
 * Created by lyr on 2017/6/9.
 */
@RestController
@RequestMapping(value = "/authentication")
@Api(value = "认证授权", description = "认证授权")
public class AuthenticationController extends BaseController {

    @Value("${jwt.header}")
    private String tokenHeader;

    @Autowired
    private AuthenticationService authService;

    @RequestMapping(value = "/access_token", method = RequestMethod.POST)
    @ApiOperation("获取token")
    public ResponseData createAuthenticationToken(
            @RequestBody @ApiParam JwtAuthenticationRequest auth){
        try {
            String token = authService.authenticate(auth.getAppId(), auth.getAppKey());
            return success("获取accessToken成功", new JwtAuthenticationResponse(token));
        } catch (Exception e) {
            return error("获取accessToken失败");
        }
    }
}
