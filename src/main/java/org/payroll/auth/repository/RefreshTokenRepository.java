package org.payroll.auth.repository;

import org.payroll.auth.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    //void deleteByUserId(Long userId);
    int deleteByUserId(Long userId);
}