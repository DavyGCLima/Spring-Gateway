package com.CodeCrusades.GraalGatewayTest.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Optional;

//Service Disabled in favor of CustomAuthenticationSuccessHandler, since it will run over Oidic and OAuth2
//@Service
public class CustomOAuth2UserService extends DefaultReactiveOAuth2UserService {

    public CustomOAuth2UserService() {
        System.out.println("============== LOADING USER SERVICE");
    }

    @Autowired
    private PersistUser userService;

    private final DefaultReactiveOAuth2UserService delegate = new DefaultReactiveOAuth2UserService();

    @Override
    public Mono<OAuth2User> loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("call load user ======================================================");
        Mono<OAuth2User> user =  super.loadUser(userRequest);
        try {
            return userService.processOAuth2User(Optional.of(userRequest), delegate.loadUser(userRequest).block(), userRequest.getClientRegistration().getClientName());
//            return processOAuth2User(userRequest, user);
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

}
