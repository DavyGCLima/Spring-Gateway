package com.CodeCrusades.GraalGatewayTest.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import javax.naming.AuthenticationException;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;

@Component
public class CustomAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {

    private RedirectServerAuthenticationSuccessHandler defaulthandler = new RedirectServerAuthenticationSuccessHandler();

    @Autowired
    private PersistUser userService;
    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        var principal = authentication.getPrincipal();

//        Mono<OAuth2User> user = principal.cast(Authentication.class)
//                .map(Authentication::getPrincipal)
//                .cast(OAuth2User.class);

        OAuth2User user = new DefaultOAuth2User(((OAuth2User)principal).getAuthorities(), ((OAuth2User)principal).getAttributes(), "name");

        try {
            userService.processOAuth2User(Optional.empty(), user);
        } catch (AuthenticationException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        return defaulthandler.onAuthenticationSuccess(webFilterExchange, authentication);
    }
}
