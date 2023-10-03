package com.demo.jwt.service;

import com.demo.jwt.auth.AuthenticationRequest;
import com.demo.jwt.dto.AuthenticationRespond;
import com.demo.jwt.auth.RegisterRequest;
import com.demo.jwt.dto.RefreshTokenRequest;
import com.demo.jwt.repository.RefreshTokenRepository;
import com.demo.jwt.repository.UserRepository;
import com.demo.jwt.user.RefreshToken;
import com.demo.jwt.user.Role;
import com.demo.jwt.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;


    @Autowired
    private RefreshTokenService  refreshTokenService;


    public AuthenticationRespond register(RegisterRequest request) {
        Optional<User> byEmail = repository.findByEmail(request.getEmail());
        if(byEmail.isPresent()){
            throw new IllegalStateException("Email Taken");
        }
        var user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.valueOf(request.getRole()))
                .build();
        repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = refreshTokenService.createRefreshToken(user.getEmail());
        return AuthenticationRespond.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken.getToken())
                .build();
    }

    public AuthenticationRespond authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = refreshTokenService.createRefreshToken(user.getEmail());
        return AuthenticationRespond.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken.getToken())
                .build();
    }

    public AuthenticationRespond refreshToken(RefreshTokenRequest request){
        return refreshTokenService.findByToken(request.getToken())
                .map(refreshTokenService::verifyExperiation)
                .map(RefreshToken::getUserInfo)
                .map( userInfo-> {
                    var user = repository.findByEmail(userInfo.getEmail()).orElseThrow();
                    var jwtToken= jwtService.generateToken(user);
                   return AuthenticationRespond.builder()
                           .accessToken(jwtToken)
                           .refreshToken(request.getToken())
                           .build();

                }).orElseThrow(() -> new RuntimeException("Refresh token is not in database"));

    }



}
