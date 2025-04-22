package org.payroll.auth.service;

import lombok.RequiredArgsConstructor;
import org.payroll.auth.entity.RefreshToken;
import org.payroll.auth.entity.User;
import org.payroll.auth.repository.RefreshTokenRepository;
import org.payroll.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenService.class);

    @Value("${jwt.refreshExpiration}")
    private Long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public RefreshToken createRefreshToken(Long userId) {
        logger.info("Starting refresh token creation for user ID: {}", userId);

        // Delete existing tokens and force flush
        int deletedCount = deleteByUserIdAndFlush(userId);

        if (deletedCount == 0) {
            logger.warn("No existing refresh tokens found to delete for user ID: {}", userId);
        } else {
            logger.info("Deleted {} existing refresh tokens for user ID: {}", deletedCount, userId);
        }

        // Create new refresh token
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));

        try {
            RefreshToken savedToken = refreshTokenRepository.saveAndFlush(refreshToken);
            logger.info("Created new refresh token for user ID: {}, token: {}", userId, savedToken.getToken());
            return savedToken;
        } catch (Exception e) {
            logger.error("Failed to save refresh token for user ID: {}. Reason: {}", userId, e.getMessage(), e);
            throw e;
        }
    }

    public boolean isExpired(RefreshToken token) {
        return token.getExpiryDate().isBefore(Instant.now());
    }

    @Transactional
    public int deleteByUserIdAndFlush(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));
        int deleted = refreshTokenRepository.deleteByUserId(userId);
        refreshTokenRepository.flush(); // Explicit flush after deletion
        logger.info("Deleted {} refresh tokens for user ID: {} and flushed changes", deleted, userId);
        return deleted;
    }

    public void deleteByUserId(Long id) {
    }
}