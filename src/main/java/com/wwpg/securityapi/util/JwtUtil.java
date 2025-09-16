package com.wwpg.securityapi.util;

import com.wwpg.securityapi.user.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtil {
    private final SecretKey key = Jwts.SIG.HS256.key().build(); // 서명 키 (랜덤 생성)

    // Access Token 0생성
    public String generateAccessToken(User user) {
        final long accessTokenValidity = 15 * 60 * 1000L; // 15분

        return Jwts.builder()
                .subject(String.valueOf(user.getEmail()))
                .claim("role", user.getRole())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + accessTokenValidity))
                .signWith(key)
                .compact();
    }

    public String generateAccessToken(String email) {
        final long accessTokenValidity = 15 * 60 * 1000L; // 15분

        return Jwts.builder()
                .subject(String.valueOf(email))
                .claim("role", "USER") // roleSet도 claim에 추가
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + accessTokenValidity))
                .signWith(key)
                .compact();
    }

    // Refresh Token 생성 ==> Access Token이 만료되었을때 재생성하기 위한 토큰(필요정보최소화)
    public String generateRefreshToken(User user) {
        final long refreshTokenValidity = 7 * 24 * 60 * 60 * 1000L; // 7일

        return Jwts.builder()
                .subject(String.valueOf(user.getEmail()))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + refreshTokenValidity))
                .signWith(key)
                .compact();
    }

    public String generateRefreshToken(String email) {
        final long refreshTokenValidity = 7 * 24 * 60 * 60 * 1000L; // 7일

        return Jwts.builder()
                .subject(String.valueOf(email))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + refreshTokenValidity))
                .signWith(key)
                .compact();
    }

    // 토큰에서 사용자 ID 추출
    public String getEmailFromToken(String token) {
        Claims claims = parseClaims(token);
        return claims.getSubject();
    }

    // 토큰에서 role 추출
    public String getUserRoleFromToken(String token) {
        Claims claims = parseClaims(token);
        return claims.get("role", String.class);
    }

    // 토큰 유효성 검사
    public boolean validateToken(String token) {
        try {
            parseClaims(token); // 파싱 성공 == 유효함
            return true;
        } catch (ExpiredJwtException e) {
            System.out.println("JWT 만료됨");
        } catch (JwtException e) {
            System.out.println("JWT 유효하지 않음");
        }
        return false;
    }

    // Claims 파싱
    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // 토큰 만료 시간 가져오기
    public Date getExpiration(String token) {
        return parseClaims(token).getExpiration();
    }

}
