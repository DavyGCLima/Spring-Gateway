package com.CodeCrusades.GraalGatewayTest.security;

import com.CodeCrusades.GraalGatewayTest.service.CustomOAuth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;


@Configuration
@EnableWebFluxSecurity
public class SecurityConfiguration {


    @Bean
    public ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauthUserService() {
        return new CustomOAuth2UserService();
    }

    @Bean
    public MapReactiveUserDetailsService userDetailsService() {
        UserDetails user = User
                .withUsername("masteruser")
                .password("abacate")
                .roles("ADMIN")
                .build();
        return new MapReactiveUserDetailsService(user);
    }

//    @Bean
//    public ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
//        final DefaultReactiveOAuth2UserService delegate = new DefaultReactiveOAuth2UserService();
//
//        return (userRequest) -> {
//            // Delegate to the default implementation for loading a user
//            return delegate.loadUser(userRequest)
//                    .flatMap((oAuthUser) -> {
//                        OAuth2AccessToken accessToken = userRequest.getAccessToken();
//                        Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
//
//                        // TODO
//                        // 1) Fetch the authority information from the protected resource using accessToken
//                        // 2) Map the authority information to one or more GrantedAuthority's and add it to mappedAuthorities
//
//                        // 3) Create a copy of oidcUser but use the mappedAuthorities instead
//                        oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
//
//                        return Mono.just(oidcUser);
//                    });
//        };
//    }

    @Bean
    public SecurityWebFilterChain configure(ServerHttpSecurity http) throws Exception {
        return http
                .authorizeExchange((exchanges) ->
                        exchanges
                                .pathMatchers("/oauth2/**", "/gateway/**", "/test/**", "/auth/**", "/login/**").permitAll()
                                // any URL that starts with /admin/ requires the role "ROLE_ADMIN"
                                .pathMatchers("/admin/**").hasRole("ADMIN")
                                // a POST to /users requires the role "USER_POST"
                                .pathMatchers(HttpMethod.POST, "/users").hasAuthority("USER_POST")
                                // a request to /users/{username} requires the current authentication's username
                                // to be equal to the {username}
//                                .pathMatchers("/users/{username}").access((authentication, context) ->
//                                        authentication
//                                                .map(Authentication::getName)
//                                                .map((username) -> username.equals(context.getVariables().get("username")))
//                                                .map(AuthorizationDecision::new)
//                                )
                                // allows providing a custom matching strategy that requires the role "ROLE_CUSTOM"
//                                .matchers(customMatcher).hasRole("CUSTOM")
                                // any other request requires the user to be authenticated
                                .anyExchange().authenticated()
                )
                .oauth2Login((oauth2Login) ->
                    oauth2Login
                        .authenticationMatcher(new PathPatternParserServerWebExchangeMatcher("/login/oauth2/code/{registrationId}"))
        )
//                .authenticationSuccessHandler()
//                .authenticationFailureHandler()
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .build();


//        http
//                .csrf().disable().cors().and()
//                .authorizeRequests()
//                .antMatchers("/oauth2/**").permitAll()
//                .anyRequest().authenticated()
//                .and()
//                .formLogin().disable()
//                .oauth2Login()
//                .authorizationEndpoint()
//                .baseUri("/oauth2/authorize")
//                .authorizationRequestRepository(cookieAuthorizationRequestRepository())
//                .and()
//                .userInfoEndpoint()
//                .userService(oauthUserService);
//                .and()
//                .successHandler(oAuth2AuthenticationSuccessHandler)
//                .failureHandler(oAuth2AuthenticationFailureHandler);

//        return http.build();
    }

    @Bean
    public ReactiveOAuth2AuthorizedClientManager authorizedClientManager(
            ReactiveClientRegistrationRepository clientRegistrationRepository,
            ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {

        ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider =
                ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
                        .authorizationCode()
                        .refreshToken()
                        .clientCredentials()
                        .password()
                        .build();

        DefaultReactiveOAuth2AuthorizedClientManager authorizedClientManager =
                new DefaultReactiveOAuth2AuthorizedClientManager(
                        clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        return authorizedClientManager;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers("/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**");
    }

}
