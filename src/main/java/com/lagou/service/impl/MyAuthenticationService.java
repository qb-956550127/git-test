package com.lagou.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


@Service
public class MyAuthenticationService implements AuthenticationSuccessHandler,AuthenticationFailureHandler,LogoutSuccessHandler {

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();


    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        System.out.println("登录成功后续处理。。。");

        //重定向到index页面
        //redirectStrategy.sendRedirect(httpServletRequest,httpServletResponse,"/");

        Map result = new HashMap<>();
        result.put("code",HttpStatus.OK.value());
        result.put("message","登录成功");

        httpServletResponse.setContentType("application/json;charset=UTF-8");

        httpServletResponse.getWriter().write(objectMapper.writeValueAsString(result));
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        System.out.println("登录失败后续处理。。。");

        //redirectStrategy.sendRedirect(httpServletRequest,httpServletResponse,"/toLoginPage");

        Map result = new HashMap();
        result.put("code",HttpStatus.UNAUTHORIZED.value());//设置响应码
        result.put("message",e.getMessage());//设置错误信息
        httpServletResponse.setContentType("application/json;charset=UTF-8");

        httpServletResponse.getWriter().write(objectMapper.writeValueAsString(result));


    }

    @Override
    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        System.out.println("onLogoutSuccess");
        redirectStrategy.sendRedirect(httpServletRequest,httpServletResponse,"toLoginPage");
    }
}
