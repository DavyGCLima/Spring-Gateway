package com.CodeCrusades.GraalGatewayTest.service;

import com.CodeCrusades.GraalGatewayTest.domain.Provider;
import com.CodeCrusades.GraalGatewayTest.domain.User;
import com.CodeCrusades.GraalGatewayTest.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import javax.naming.AuthenticationException;
import java.util.*;

//@Service
public class CustomOAuth2UserService extends DefaultReactiveOAuth2UserService {

    public CustomOAuth2UserService() {
        System.out.println("============== LOADING USER SERVICE");
    }

    @Autowired
    private UserRepository userRepository;

//    private final DefaultReactiveOAuth2UserService delegate = new DefaultReactiveOAuth2UserService();

    @Override
    public Mono<OAuth2User> loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("call load user ======================================================");
        Mono<OAuth2User> user =  super.loadUser(userRequest);
        return user;
//        try {
////            return processOAuth2User(userRequest, delegate.loadUser(userRequest));
//            return processOAuth2User(userRequest, user);
//        } catch (Exception ex) {
//            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
//            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
//        }
    }

    private Mono<OAuth2User> processOAuth2User(OAuth2UserRequest oAuth2UserRequest, Mono<OAuth2User> oAuth2User) throws AuthenticationException {
        if(oAuth2User.blockOptional().isEmpty()) {
            throw new AuthenticationException("Cannot load user base data from web");
        }
        if(StringUtils.isEmpty(Objects.requireNonNull(oAuth2User.block()).getAttributes().get("email"))) {
            throw new AuthenticationException("Email not found from OAuth2 provider");
        }

        OAuth2User baseUser = oAuth2User.block();

        Optional<User> userOptional = userRepository.findByEmail((String) baseUser.getAttributes().get("email"));
        User user;
        if(userOptional.isPresent()) {
            user = userOptional.get();
            if(!user.getProvider().equals(Provider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()))) {
                throw new AuthenticationException("Looks like you're signed up with " +
                        user.getProvider() + " account. Please use your " + user.getProvider() +
                        " account to login.");
            }
            user = setUserDataNullable(user, baseUser, oAuth2UserRequest);
        } else {
            user = registerNewUser(oAuth2UserRequest, baseUser);
        }

        return Mono.just(User.create(user, baseUser.getAttributes()));
    }

    private User registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2UserInfo) {
        User user = new User();
        setUserDataNullable(user, oAuth2UserInfo, oAuth2UserRequest);
        userRepository.save(user);
        return user;
    }

    private User setUserDataNullable(User user, OAuth2User oAuth2User, OAuth2UserRequest oAuth2UserRequest) {
        if(user == null) {
            User newUser = new User();
            setUserData(newUser, oAuth2User, oAuth2UserRequest);
            return newUser;
        }

        setUserData(user, oAuth2User, oAuth2UserRequest);
        return user;
    }

    private void setUserData(User user, OAuth2User oAuth2User, OAuth2UserRequest oAuth2UserRequest) {
        user.setProvider(Provider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()));
        user.setProviderId((String) oAuth2User.getAttributes().get("sub"));
        user.setPassword((String) oAuth2User.getAttributes().get("sub"));
        user.setName((String) oAuth2User.getAttributes().get("given_name"));
        user.setEmail((String) oAuth2User.getAttributes().get("email"));
        user.setIsLocked(false);
    }

}
