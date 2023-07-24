package com.CodeCrusades.GraalGatewayTest.filters;

import com.CodeCrusades.GraalGatewayTest.repository.UserRepository;
import io.micrometer.common.util.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import com.CodeCrusades.GraalGatewayTest.domain.User;

import javax.naming.AuthenticationException;
import java.util.Objects;
import java.util.Optional;

//@Component
public class OAuth2UserFilter implements WebFilter {

    @Autowired
    private UserRepository userRepository;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return exchange.getPrincipal()
                .cast(Authentication.class)
                .map(Authentication::getPrincipal)
                .cast(User.class)
                .doOnNext(oauth2User -> {
                    System.out.println(" -> filter");
                    try {
                        processOAuth2User(oauth2User);
                    } catch (AuthenticationException e) {
                        e.printStackTrace();
                        throw new RuntimeException(e);
                    }
                })
                .then(chain.filter(exchange));
    }

    private Mono<OAuth2User> processOAuth2User(OAuth2User oAuth2User) throws AuthenticationException {
        if(oAuth2User == null) {
            throw new AuthenticationException("Cannot load user base data from web");
        }
        if(StringUtils.isEmpty((String) Objects.requireNonNull(oAuth2User).getAttributes().get("email"))) {
            throw new AuthenticationException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findByEmail((String) oAuth2User.getAttributes().get("email"));
        User user;
        if(userOptional.isPresent()) {
            user = userOptional.get();
//            if(!user.getProvider().equals(Provider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()))) {
//                throw new AuthenticationException("Looks like you're signed up with " +
//                        user.getProvider() + " account. Please use your " + user.getProvider() +
//                        " account to login.");
//            }
            user = setUserDataNullable(user, oAuth2User);
        } else {
            user = registerNewUser(oAuth2User);
        }

        return Mono.just(User.create(user, oAuth2User.getAttributes()));
    }

    private User registerNewUser(OAuth2User oAuth2UserInfo) {
        User user = new User();
        setUserDataNullable(user, oAuth2UserInfo);
        userRepository.save(user);
        return user;
    }

    private User setUserDataNullable(User user, OAuth2User oAuth2User) {
        if(user == null) {
            User newUser = new User();
            setUserData(newUser, oAuth2User);
            return newUser;
        }

        setUserData(user, oAuth2User);
        return user;
    }

    private void setUserData(User user, OAuth2User oAuth2User) {
//        user.setProvider(Provider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()));
        user.setProviderId((String) oAuth2User.getAttributes().get("sub"));
        user.setPassword((String) oAuth2User.getAttributes().get("sub"));
        user.setName((String) oAuth2User.getAttributes().get("given_name"));
        user.setEmail((String) oAuth2User.getAttributes().get("email"));
        user.setIsLocked(false);
    }
}
