package com.bypogodkin.spring.security.oauth.module.config;

import com.bypogodkin.spring.security.oauth.module.domain.CustomOAuth2User;
import com.bypogodkin.spring.security.oauth.module.service.CustomOAuth2UserService;
import com.bypogodkin.spring.security.oauth.module.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
    @Autowired
    private CustomOAuth2UserService oauthUserService;

    @Autowired
    private UserService userService;

    private static final String ANT_MATCHERS = "//login/oauth/**";
    private static final String LOGIN_PAGE = "/login";
    private static final String USER_DATA_EMAIL = "/email";
    private static final String USER_DATA_PASSWORD = "/password";
    private static final String DEFAULT_SUCCESS_URL = "/list";


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                .requestMatchers(ANT_MATCHERS).permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin().permitAll()
                .loginPage(LOGIN_PAGE)
                .usernameParameter(USER_DATA_EMAIL)
                .passwordParameter(USER_DATA_PASSWORD)
                .defaultSuccessUrl(DEFAULT_SUCCESS_URL)
                .and()
                .oauth2Login()
                .loginPage(LOGIN_PAGE)
                .userInfoEndpoint()
                .userService(oauthUserService)
                .and()
                .successHandler(new AuthenticationSuccessHandler() {

                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                        Authentication authentication) throws IOException, ServletException {
                        System.out.println("AuthenticationSuccessHandler invoked");
                        System.out.println("Authentication name: " + authentication.getName());
                        CustomOAuth2User oauthUser = (CustomOAuth2User) authentication.getPrincipal();

                        userService.processOAuthPostLogin(oauthUser.getEmail());

                        response.sendRedirect(DEFAULT_SUCCESS_URL);
                    }
                })
                //.defaultSuccessUrl("/list")
                .and()
                .logout().logoutSuccessUrl("/").permitAll()
                .and()
                .exceptionHandling().accessDeniedPage("/403")
        ;
        return http.build();
    }
}