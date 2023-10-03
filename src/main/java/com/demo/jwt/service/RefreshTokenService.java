package com.demo.jwt.service;

import com.demo.jwt.dto.RefreshTokenRequest;
import com.demo.jwt.repository.RefreshTokenRepository;
import com.demo.jwt.repository.UserRepository;
import com.demo.jwt.user.RefreshToken;
import com.demo.jwt.user.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {
    @Autowired
    private RefreshTokenRepository tokenRepository;
    @Autowired
    private UserRepository userRepository;


    public RefreshToken createRefreshToken(String email){
        RefreshToken refreshToken = RefreshToken
                .builder()
                .userInfo(userRepository.findByEmail(email).get())
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(600000))
                .build();
        return tokenRepository.save(refreshToken);
    }


    public Optional<RefreshToken> findByToken(String token){
        return  tokenRepository.findByToken(token);
    }

    public RefreshToken verifyExperiation(RefreshToken token){
        if(token.getExpiryDate().compareTo(Instant.now())<0){
            tokenRepository.delete(token);
            throw new RuntimeException(token.getToken() + "Refresh token was expeired");
        }
        return token;
    }

    public void logout(RefreshTokenRequest request) {
        String token = request.getToken();
        Optional<RefreshToken> byToken = tokenRepository.findByToken(request.getToken());
        if(byToken.isPresent()){
            tokenRepository.deleteByToken(byToken);
        }
    }
}
