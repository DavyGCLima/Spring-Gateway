package com.CodeCrusades.GraalGatewayTest.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("/rosa")
public class GatewayAPI {

    @GetMapping("/test")
    public ResponseEntity<String> test() {
        return new ResponseEntity<>("TEstado", HttpStatus.OK);
    }

}
