package com.wwpg.securityapi.security.handler;

import com.wwpg.securityapi.user.entity.User;
import com.wwpg.securityapi.user.entity.UserRole;
import com.wwpg.securityapi.user.repository.UserRepository;
import com.wwpg.securityapi.util.CookieUtil;
import com.wwpg.securityapi.util.JwtUtil;
import com.wwpg.securityapi.util.RedisUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.Optional;


@Log4j2
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {
  private final JwtUtil jwtUtil;
  private final RedisUtil redisUtil;
  private final CookieUtil cookieUtil;
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  public OAuth2SuccessHandler(JwtUtil jwtUtil
          , RedisUtil redisUtil
          , CookieUtil cookieUtil
          , UserRepository userRepository
          , PasswordEncoder passwordEncoder) {
    this.jwtUtil = jwtUtil;
    this.redisUtil = redisUtil;
    this.cookieUtil = cookieUtil;
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request
          , HttpServletResponse response
          , Authentication authentication)
          throws IOException, ServletException {
    // 소셜로그인 사용자 확인
    OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
    String email = oAuth2User.getAttribute("email");

    Optional<User> userOpt = userRepository.findByEmail(email);

    if (userOpt.isEmpty()) {
      // 사용자 추가
      User user = User.builder()
              .email(email)
              .fromSocial(true)
              .password(passwordEncoder.encode("1111"))
              .role(UserRole.USER)
              .build();

      userRepository.save(user);
    }
    else {
      if (!userOpt.get().isFromSocial()) {
        // 아이디 중복
        log.warn("기존 일반 계정과 이메일이 중복됩니다: {}", email);

        // JavaScript로 부모창에 에러 메시지 전달 (또는 서버 로그만 출력하고 닫기)
        String script = "<script>" +
                "window.opener.postMessage({ error: '이미 해당 이메일로 가입된 일반 계정이 있습니다.' }, 'http://localhost:5173');" +
                "window.close();" +
                "</script>";

        response.setContentType("text/html;charset=UTF-8");
        response.getWriter().write(script);
        return;
      }
      System.out.println("가입은 되어있고 로그인만 처리");
    }


    // accessToken, refreshToken 생성
    String accessToken = jwtUtil.generateAccessToken(email);
    String refreshToken = jwtUtil.generateRefreshToken(email);

    // Redis 저장
    redisUtil.saveRefreshToken(email, refreshToken, 7 * 24* 60 * 60);
    // JS 접근 못하는 HttpOnly 쿠키로 Refresh Token 저장
    cookieUtil.createCookie(response, "refreshToken", refreshToken, 7 * 24 * 60 * 60);

    String script = "<script>" +
            "window.opener.postMessage({ accessToken: '" + accessToken + "' }, 'http://localhost:5173');" +
            "window.close();" +
            "</script>";

    response.setContentType("text/html;charset=UTF-8");

    System.out.println(accessToken);
    System.out.println("소셜로그인 성공");

    response.getWriter().write(script);
  }
}
