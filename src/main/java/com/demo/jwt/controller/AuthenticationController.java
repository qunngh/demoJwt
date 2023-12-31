package com.demo.jwt.controller;

import com.demo.jwt.auth.AuthenticationRequest;
import com.demo.jwt.auth.RegisterRequest;
import com.demo.jwt.dto.AuthenticationRespond;
import com.demo.jwt.dto.RefreshTokenRequest;
import com.demo.jwt.service.AuthenticationService;
import com.demo.jwt.service.RefreshTokenService;
import com.demo.jwt.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;
    private final RefreshTokenService tokenService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationRespond> register(
            @RequestBody RegisterRequest request
            ){
        return ResponseEntity.ok(service.register(request));
    }


    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationRespond> register(
            @RequestBody AuthenticationRequest request

    ){

        return ResponseEntity.ok(service.authenticate(request));

    }

    @PostMapping("/refreshToken")
    public ResponseEntity<AuthenticationRespond> refreshRoken(
            @RequestBody RefreshTokenRequest refreshTokenRequest
    ){
        return ResponseEntity.ok(service.refreshToken(refreshTokenRequest));
    }
    

    @DeleteMapping("/logout")
    public void revokedToken (@RequestBody RefreshTokenRequest token){
        tokenService.logout(token);
    }
}
