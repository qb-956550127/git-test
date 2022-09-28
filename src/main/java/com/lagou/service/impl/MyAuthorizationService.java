package com.lagou.service.impl;



import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;


@Component
public class MyAuthorizationService {



    public boolean check(Authentication authentication, HttpServletRequest request){


        org.springframework.security.core.userdetails.User user = (org.springframework.security.core.userdetails.User) authentication.getPrincipal();
        // 获取用户所有权限
        Collection<GrantedAuthority> authorities = user.getAuthorities();
        // 获取用户名
        String username = user.getUsername();
        // 如果用户名为admin,则不需要认证
        if (username.equalsIgnoreCase("admin")) {
            return true;
        } else {
            // 循环用户的权限, 判断是否有ROLE_ADMIN权限, 有返回true
            for (GrantedAuthority authority : authorities) {
                String role = authority.getAuthority();
                if ("ROLE_ADMIN".equals(role)) {
                    return true;
                }
            }
        }
        return false;


    }

    /**
     * 检查用户是否有对应的访问权限
     *
     * @param authentication 登录用户
     * @param request 请求对象
     * @param id 参数ID
     * @return
     */
    public boolean check(Authentication authentication, HttpServletRequest
            request, Integer id) {
        if (id > 10) {
            return false;
        }
        return true;
    }





}
