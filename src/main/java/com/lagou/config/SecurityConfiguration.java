package com.lagou.config;

import com.lagou.domain.Permission;
import com.lagou.handle.MyAccessDeniedHandler;
import com.lagou.service.PermissionService;
import com.lagou.service.impl.MyAuthenticationService;
import com.lagou.service.impl.MyUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.sql.DataSource;
import java.util.List;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)//开启注解支持
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService myUserDetailService;


    @Autowired
    MyAuthenticationService myAuthenticationService;

    @Autowired
    MyAccessDeniedHandler myAccessDeniedHandler;


    @Autowired
    PermissionService permissionService;


    @Override
    protected void configure(HttpSecurity http) throws Exception{

        //设置/user开头的请求需要ADMIN权限
//        http.authorizeRequests().antMatchers("/user/**").hasRole("ADMIN");
//        //设置product开头的请求需要ADMIN或者PRODUCT权限，并且访问的ip是127.0.0.1
//        http.authorizeRequests().antMatchers("/product/**").access("hasAnyRole('ADMIN','PRODUCT') and hasIpAddress('127.0.0.1')");

        //使用自定义并完成授权
//        http.authorizeRequests().antMatchers("/user/**")
//                .access("@myAuthorizationService.check(authentication,request)");

        //使用自定义Bean授权,并携带路径参数
//        http.authorizeRequests().antMatchers("/user/delete/{id}").
//                access("@myAuthorizationService.check(authentication,request,#id)");


        List<Permission> list = permissionService.list();
        for (Permission permission : list) {
            //添加请求权限
            http.authorizeRequests().antMatchers(permission.getPermissionUrl()).hasAuthority(permission.getPermissionTag());
        }


        //自定义权限不足输出
        http.exceptionHandling().accessDeniedHandler(myAccessDeniedHandler);

        http.formLogin().loginPage("/toLoginPage")//开启表单验证
        .loginProcessingUrl("/login") //登录处理url
        .usernameParameter("username") //修改自定义表单name值
        .passwordParameter("password")
        .successForwardUrl("/")//登录成功之后跳转的路径
                .successHandler(myAuthenticationService)
                .failureHandler(myAuthenticationService)
                .and().logout().logoutUrl("/logout")//设置退出url
                .logoutSuccessHandler(myAuthenticationService)//自
                // 定义退出处理
        .and().rememberMe()//开启记住我功能
        .tokenValiditySeconds(1209600)//token失效时间，默认是两周
        .rememberMeParameter("remember-me")//自定义表单input 值
                .tokenRepository(getPersistentTokenRepository())
        .and()
        .authorizeRequests().antMatchers("/toLoginPage").permitAll()//放行登录页
        .anyRequest().authenticated();//所有请求都需要登录认证才能访问

        //关闭csrf防护
        http.csrf().disable();
        //开启csrf防护，定义哪些路径 不需要保护
        //http.csrf().ignoringAntMatchers("/user/saveOrUpdate");


        //加载同源域名下iframe加载页面
        http.headers().frameOptions().sameOrigin();

//        http.sessionManagement()    //设置session管理
//                .invalidSessionUrl("/toLoginPage") //session无效后跳转的路径，默认是登录页面
//                .maximumSessions(1) //session最大会话数量，同一时间只能有一个用户可以登录     互踢
//                .maxSessionsPreventsLogin(true)//达到最大会话数量，就阻止登录
//                .expiredUrl("/toLoginPage");//session过期跳转的路径


        //开启跨域支持
        http.cors().configurationSource(corsConfigurationSource());



    }


    @Override
    public void configure(WebSecurity web) throws Exception{
        //解决静态资源被拦截的问题
        web.ignoring().antMatchers("/css/**","/images/**","/js/**","/favicon.ico");
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth.userDetailsService(myUserDetailService);//使用自定义用户认证
    }


    @Autowired
    DataSource dataSource;

    /**
     * 负责token与数据库之间的操作
     */


    @Bean
    public PersistentTokenRepository getPersistentTokenRepository(){
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);//设置数据源
        //tokenRepository.setCreateTableOnStartup(false);//启动时帮助我们自动创建一张表，第一次启动设置为true，第二次设置false或者注释

        return tokenRepository;
    }

    /**
     * 跨域配置信息源
     */


    public CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        //允许跨域的站点
        corsConfiguration.addAllowedOrigin("*");

        //允许跨域的http方法
        corsConfiguration.addAllowedMethod("*");

        //允许跨域的请求头
        corsConfiguration.addAllowedHeader("*");

        //允许带凭证
        corsConfiguration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();

        //对所有url生效
        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**",corsConfiguration);

        return urlBasedCorsConfigurationSource;
    }





}
