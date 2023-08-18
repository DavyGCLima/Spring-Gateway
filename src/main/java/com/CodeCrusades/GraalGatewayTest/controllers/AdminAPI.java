package com.CodeCrusades.GraalGatewayTest.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Collection;

@RestController
@RequestMapping(path = "/admin")
public class AdminAPI {

    @GetMapping("/is-admin")
//    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public Mono<ResponseEntity<Boolean>> isAdmin(Authentication authentication) {
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        return Mono.just(ResponseEntity.ok().build());
    }

    @GetMapping("/has-role")
//    @PreAuthorize("hasRole('ROLE_USER')")
    public Mono<ResponseEntity<Void>> isUser(Authentication authentication){
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        return Mono.just(ResponseEntity.ok().build());
    }

    @GetMapping()
    public Mono<ResponseEntity<Void>> isAuthenticated(Authentication authentication) {
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        return Mono.just(ResponseEntity.ok().build());
    }
}
