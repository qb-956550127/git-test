package com.lagou.service.impl;

import com.lagou.domain.Permission;
import com.lagou.domain.User;
import com.lagou.service.PermissionService;
import com.lagou.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
public class MyUserDetailService implements UserDetailsService {


    @Autowired
    private UserService userService;

    @Autowired
    private PermissionService permissionService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userService.findByUsername(username);

        if(user == null){
            throw new UsernameNotFoundException(username);
        }

        //声明一个权限集合，因为构造方法里面不能传入null
        Collection<GrantedAuthority> authorities = new ArrayList<>();
//        if(username.equalsIgnoreCase("admin")){
//            authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
//        }else {
//            authorities.add(new SimpleGrantedAuthority("ROLE_PRODUCT"));
//        }

        List<Permission> permissions = permissionService.findByUserId(user.getId());

        for (Permission permission : permissions) {
            authorities.add(new SimpleGrantedAuthority(permission.getPermissionTag()));
        }



        //需要返回一个springSecurity的UserDetails对象
        UserDetails userDetails = new org.springframework.security.core.userdetails.User(user.getUsername(),"{bcrypt}"+ user.getPassword(),//{noop}表示不加密认证。
                true,//用户是否启用 true 代表启用
                true,//用户是否过期  true 代表未过期
                true,//用户凭据是否过期 true 代表未过期
                true,//用户是否锁定 true 代表未锁定
                authorities);

        return userDetails;
    }


    public static void main(String[] args) {

        BCryptPasswordEncoder bc = new BCryptPasswordEncoder();
        String encode = bc.encode("123456");
        System.out.println(encode);
        encode = bc.encode("123456");
        System.out.println(encode);
    }
}
