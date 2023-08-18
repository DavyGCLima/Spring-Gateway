package com.CodeCrusades.GraalGatewayTest.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class GatewayAPI {

    @GetMapping("/test")
    public Mono<ResponseEntity<String>> test() {
        return Mono.just(new ResponseEntity<>("TEstado", HttpStatus.OK));
    }

}
