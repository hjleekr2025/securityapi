package com.wwpg.securityapi.util;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class RedisUtil {
    private final StringRedisTemplate redisTemplate;

    // RefreshToken 저장
    public void saveRefreshToken(String userEmail, String refreshToken, long expirationInSeconds) {
        redisTemplate.opsForValue().set(
                "RT:" + userEmail,
                refreshToken,
                expirationInSeconds,
                TimeUnit.SECONDS
        );
    }

    // RefreshToken 조회
    public String getRefreshToken(String userEmail) {
        return redisTemplate.opsForValue().get("RT:" + userEmail);
    }

    // RefreshToken 삭제
    public void deleteRefreshToken(String userEmail) {
        redisTemplate.delete("RT:" + userEmail);
    }


}
