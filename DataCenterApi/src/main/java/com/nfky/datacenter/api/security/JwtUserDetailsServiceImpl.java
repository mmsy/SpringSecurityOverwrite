package com.nfky.datacenter.api.security;

import com.nfky.datacenter.api.dao.app.AppInfoRepository;
import com.nfky.datacenter.api.entity.app.AppInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by lyr on 2017/6/12.
 */
@Service
public class JwtUserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private AppInfoRepository appInfoReg;

    @Autowired
    JdbcTemplate jdbcTemplate;

    private final static String APP_ROLES_SQL = "select a.app_id,b.role from app_roles a join roles b on a.role = b.id where a.app_id = ? ";

    @Override
    public UserDetails loadUserByUsername(String appId) throws UsernameNotFoundException {
        AppInfo app = appInfoReg.findByAppId(appId);

        if (app == null) {
            throw new UsernameNotFoundException(String.format("No user found with username '%s'.", appId));
        } else {
            List<SimpleGrantedAuthority> roles = jdbcTemplate.query(APP_ROLES_SQL, new Object[]{app.getAppId()}, new RowMapper<SimpleGrantedAuthority>() {
                @Override
                public SimpleGrantedAuthority mapRow(ResultSet resultSet, int i) throws SQLException {
                    return new SimpleGrantedAuthority(resultSet.getString("role"));
                }
            });
            UserDetails userDetails = new JWTUserImp(app.getAppId(), app.getAppKey(), roles != null ? roles : new ArrayList<>(), app.getLastModifyTime());
            return userDetails;
        }
    }
}
