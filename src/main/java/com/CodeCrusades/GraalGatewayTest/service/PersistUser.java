package com.CodeCrusades.GraalGatewayTest.service;

import com.CodeCrusades.GraalGatewayTest.domain.Provider;
import com.CodeCrusades.GraalGatewayTest.domain.User;
import com.CodeCrusades.GraalGatewayTest.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import javax.naming.AuthenticationException;
import java.util.Objects;
import java.util.Optional;

@Service
public class PersistUser {
    @Autowired
    private UserRepository userRepository;

    public Mono<OAuth2User> processOAuth2User(Optional<OAuth2UserRequest> oAuth2UserRequest, OAuth2User oAuth2User, String provider) throws AuthenticationException {
        if(oAuth2User == null) {
            throw new AuthenticationException("Cannot load user base data from web");
        }
        if(StringUtils.isEmpty(Objects.requireNonNull(oAuth2User).getAttributes().get("email"))) {
            throw new AuthenticationException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findByEmail((String) oAuth2User.getAttributes().get("email"));
        User user;
        if(userOptional.isPresent()) {
            user = userOptional.get();
            if(oAuth2UserRequest.isPresent() && !user.getProvider()
                    .equals(Provider.valueOf(oAuth2UserRequest.get().getClientRegistration().getRegistrationId()))
            ) {
                throw new AuthenticationException("Looks like you're signed up with " +
                        user.getProvider() + " account. Please use your " + user.getProvider() +
                        " account to login.");
            }
            user = setUserDataNullable(user, oAuth2User, oAuth2UserRequest, provider);
        } else {
            user = registerNewUser(oAuth2UserRequest, oAuth2User, provider);
        }

        return Mono.just(User.create(user, oAuth2User.getAttributes(), Provider.valueOf(provider.toUpperCase())));
    }

    private User registerNewUser(Optional<OAuth2UserRequest> oAuth2UserRequest, OAuth2User oAuth2UserInfo, String provider) {
        User user = setUserDataNullable(null, oAuth2UserInfo, oAuth2UserRequest, provider);
        userRepository.save(user);
        return user;
    }

    private User setUserDataNullable(User user, OAuth2User oAuth2User, Optional<OAuth2UserRequest> oAuth2UserRequest, String provider) {
        if(user == null) {
            User newUser = new User();
            setUserData(newUser, oAuth2User, oAuth2UserRequest, provider);
            return newUser;
        }

        setUserData(user, oAuth2User, oAuth2UserRequest, provider);
        return user;
    }

    private void setUserData(User user, OAuth2User oAuth2User, Optional<OAuth2UserRequest> oAuth2UserRequest, String provider) {
        oAuth2UserRequest.ifPresent(auth2UserRequest -> user.setProvider(Provider.valueOf(auth2UserRequest.getClientRegistration().getRegistrationId())));
        user.setProviderId((String) oAuth2User.getAttributes().get("sub"));
        user.setPassword((String) oAuth2User.getAttributes().get("sub"));
        user.setName((String) oAuth2User.getAttributes().get("given_name"));
        user.setEmail((String) oAuth2User.getAttributes().get("email"));
        user.setIsLocked(false);
        user.setProvider(Provider.valueOf(provider.toUpperCase()));
    }

}
