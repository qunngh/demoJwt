package com.demo.jwt.repository;

import com.demo.jwt.user.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken,Integer> {


    Optional<RefreshToken> findByToken(String token);

    void deleteByToken(Optional<RefreshToken> byToken);
}
