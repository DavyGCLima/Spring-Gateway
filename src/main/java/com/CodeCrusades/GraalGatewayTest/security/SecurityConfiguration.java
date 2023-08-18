package com.CodeCrusades.GraalGatewayTest.security;

import com.CodeCrusades.GraalGatewayTest.service.CustomAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
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
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import reactor.core.publisher.Mono;


@Configuration
@EnableWebFluxSecurity
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfiguration {

//    private OAuth2UserFilter oAuth2UserFilter;

    @Bean
    public MapReactiveUserDetailsService userDetailsService() {
        UserDetails user = User
                .withUsername("masteruser")
                .password("abacate")
                .roles("ADMIN")
                .build();
        return new MapReactiveUserDetailsService(user);
    }

    // Another method to do the autentication
//    @Bean
//    public ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
//        CustomOAuth2UserService service = new CustomOAuth2UserService();
//        return service;
//    }


    @Autowired
    private CustomAuthenticationSuccessHandler successHandler;

    @Bean
    public SecurityWebFilterChain configure(ServerHttpSecurity http, Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter) throws Exception {
        return http
                .authorizeExchange((exchanges) ->
                        exchanges
                                .pathMatchers("/oauth2/**", "/gateway/**", "/test/**", "/auth/**", "/login/**", "/admin/**").permitAll()
                                // any URL that starts with /admin/ requires the role "ROLE_ADMIN"
//                                .pathMatchers("/admin/is-admin").hasAnyAuthority("ROLE_ADMIN")
//                                .pathMatchers("/admin/has-role").hasAnyAuthority("ROLE_USER")
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
//                .oauth2Login((oauth2Login) ->
//                    oauth2Login
//                        .authenticationMatcher(new PathPatternParserServerWebExchangeMatcher("/login/oauth2/code/{registrationId}"))
//                        .authenticationSuccessHandler(successHandler)
//                )
                .oauth2ResourceServer(oAuth2ResourceServerSpec ->
                        oAuth2ResourceServerSpec.jwt(jwtSpec ->
                                jwtSpec.jwtAuthenticationConverter(jwtAuthenticationConverter)))
//                .oauth2Login(Customizer.withDefaults())
//                .authenticationFailureHandler()
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
//                .addFilterAfter(oAuth2UserFilter, SecurityWebFiltersOrder.AUTHENTICATION)
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

//    @Bean
//    public ReactiveOAuth2AuthorizedClientManager authorizedClientManager(
//            ReactiveClientRegistrationRepository clientRegistrationRepository,
//            ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
//
//        ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider =
//                ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
//                        .authorizationCode()
//                        .refreshToken()
//                        .clientCredentials()
//                        .password()
//                        .build();
//
//        DefaultReactiveOAuth2AuthorizedClientManager authorizedClientManager =
//                new DefaultReactiveOAuth2AuthorizedClientManager(
//                        clientRegistrationRepository, authorizedClientRepository);
//        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
//
//        return authorizedClientManager;
//    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers("/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**");
    }

}
