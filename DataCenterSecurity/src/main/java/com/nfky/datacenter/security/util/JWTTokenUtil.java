package com.nfky.datacenter.security.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Date;
import java.util.Map;

/**
 * jwt工具类
 *
 * Created by lyr on 2017/6/13.
 */
public class JWTTokenUtil {
    private static final String CLAIM_KEY_USERNAME = "user_name";

    private static final String CLAIM_KEY_CREATED = "created";

    /**
     * 生成token
     *
     * @param claims  token参数
     * @param timeOut 过期时间
     * @param secret  签名KEY
     * @return
     */
    public static String produceToken(Map<String, Object> claims, long timeOut, String secret) {
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + timeOut * 1000))
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    /**
     * 从Token中获取UserName
     *
     * @param token  token
     * @param secret 签名KEY
     * @return
     */
    public static String getUserNameFromToken(String token, String secret) {
        String userName;
        try {
            final Claims claims = getClaimsFromToken(token, secret);
            userName = (String)claims.get(CLAIM_KEY_USERNAME);
        } catch (Exception e) {
            userName = null;
        }
        return userName;
    }

    /**
     * 获取Token创建时间
     *
     * @param token  token
     * @param secret 签名KEY
     * @return
     */
    public static long getCreatedTimeFromToken(String token, String secret) {
        Date created;
        try {
            final Claims claims = getClaimsFromToken(token, secret);
            created = new Date((Long) claims.get(CLAIM_KEY_CREATED));
        } catch (Exception e) {
            created = null;
        }
        return created.getTime();
    }

    /**
     * 获取过期时间
     *
     * @param token  token
     * @param secret 签名KEY
     * @return
     */
    public static long getExpiredTimeFromToken(String token, String secret) {
        Date expiration;
        try {
            final Claims claims = getClaimsFromToken(token, secret);
            expiration = claims.getExpiration();
        } catch (Exception e) {
            expiration = null;
        }
        return expiration.getTime();
    }

    public static boolean isTokenExpired(String token, String secret) {
        return getExpiredTimeFromToken(token, secret) <= System.currentTimeMillis();
    }

    /**
     * 获取Token信息
     *
     * @param token  token
     * @param secret 签名key
     * @return
     */
    private static Claims getClaimsFromToken(String token, String secret) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            claims = null;
        }
        return claims;
    }
}
