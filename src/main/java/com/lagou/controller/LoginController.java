package com.lagou.controller;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * 处理登录业务gitceshibranch--master-branch--back
 * 处理登录业务gitceshibranch--master-branch-pull
 * gayaozi
 */
@Controller
public class LoginController {
    /**
     * 跳转登录页面
     *
     * @return
     */
    @RequestMapping("/toLoginPage")
    public String toLoginPage() {
        return "login";
    }
}
