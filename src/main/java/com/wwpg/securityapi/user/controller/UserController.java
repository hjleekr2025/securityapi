package com.wwpg.securityapi.user.controller;

import com.wwpg.securityapi.user.dto.UserDTO;
import com.wwpg.securityapi.user.entity.User;
import com.wwpg.securityapi.user.repository.UserRepository;
import com.wwpg.securityapi.user.service.UserService;
import com.wwpg.securityapi.util.CookieUtil;
import com.wwpg.securityapi.util.JwtUtil;
import com.wwpg.securityapi.util.RedisUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api")
@AllArgsConstructor
@Log4j2
@CrossOrigin(origins = "http://localhost:5173", allowCredentials = "true")
public class UserController {

    private final UserService userService;
    private final UserRepository userRepository;// JPA Repository or DAO
    private final JwtUtil jwtUtil;
    private final RedisUtil redisUtil;
    private final CookieUtil cookieUtil;
    private final AuthenticationManager authenticationManager;


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserDTO userDTO, HttpServletResponse response) {

        // email과 비밀번호 체크
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(userDTO.getEmail(), userDTO.getPassword())
        );
        Optional<User> userOpt = userRepository.findByEmail(authentication.getName());
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(401).body("아이디 또는 패스워드 오류");
        }

        User user = userOpt.get();

        // 토큰 생성 - accessToken, refreshToken 생성한다.
        String accessToken = jwtUtil.generateAccessToken(user);
        String refreshToken = jwtUtil.generateRefreshToken(user);

        // Redis 저장
        redisUtil.saveRefreshToken(user.getEmail(), refreshToken, 7 * 24* 60 * 60);

        // JS 접근 못하는 HttpOnly 쿠키로 Refresh Token 저장
        cookieUtil.createCookie(response, "refreshToken", refreshToken, 7 * 24 * 60 * 60);

        // Access Token만 응답으로 보내기 => React에서는 LocalStorage에 저장하여
        // API호출시 헤더에 "Bearer "+token을 넣어 사용한다.
        return ResponseEntity.ok(Map.of("accessToken", accessToken, "user", Map.of("email", user.getEmail(), "role", user.getRole())));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody UserDTO userDTO) {
        try {
            // 회원가입처리
            User saveUser = userService.create(userDTO);
            // React로 보낼 데이터 구성
            UserDTO responseUserDTO = UserDTO.builder()
                    .email(saveUser.getEmail())
                    .id(saveUser.getId())
                    .fromSocial(saveUser.isFromSocial())
                    .build();

            return ResponseEntity.ok().body(responseUserDTO);
        }
        catch (Exception e) {
            // 400 Error 반환하는 명령 (본문이 없을때)
            return ResponseEntity.badRequest().build();
            // 본문을 사용하려면
            // return ResponseEntity.badRequest().body("이미 가입된 이메일입니다.");

        }
    }

    // 만료된 Access토큰을 사용하여 API를 호출하면 401 error를 React로 보내주고
    // React는 refresh 토큰을 요청한다. 이때 쿠키를 자동으로 보내도록 설정하여 전달하는데
    // refreshToken과 redis에 저장되어있는 token을 비교하여 유효토큰인지 검사하고
    // 유효한 토큰이면 access토큰을 다시 만들어서 react로 보내고
    // 유효하지 않은 refresh토큰이면 401에러를 보내서 로그인 페이지가 나오도록 구현한다.
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = cookieUtil.getCookie(request, "refreshToken");

        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("리플레시 토근 없음");
        }

        if (!jwtUtil.validateToken(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("유효하지 않은 토큰");
        }

        String userEmail = jwtUtil.getEmailFromToken(refreshToken);
        String savedToken = redisUtil.getRefreshToken(userEmail);

        if (!refreshToken.equals(savedToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰 불일치");
        }

        // 새 AccessToken 발급
        Optional<User> userOpt = userRepository.findByEmail(userEmail);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            String newAccessToken = jwtUtil.generateAccessToken(user);
            System.out.println("New AccessToken 발급");

            // === 추가: Refresh Token Sliding 갱신 ===
            // refresh 토큰 유효기간이 2일 이내 일 때 refresh토큰 재발급하고 redis에 저장
            long remaining = jwtUtil.getExpiration(refreshToken).getTime() - System.currentTimeMillis();
            long twoDays = 2 * 24 * 60 * 60 * 1000L;

            if (remaining < twoDays) {
                String newRefreshToken = jwtUtil.generateRefreshToken(user);
                redisUtil.saveRefreshToken(userEmail, newRefreshToken, 7 * 24 * 60 * 60);
                cookieUtil.createCookie(response, "refreshToken", refreshToken, 7 * 24 * 60 * 60);
            }

            return ResponseEntity.ok(Map.of(
                    "accessToken", newAccessToken,
                    "expiresAt", jwtUtil.getExpiration(newAccessToken),
                    "user", Map.of("email", userEmail, "role", user.getRole())
            ));
        }

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("사용자 찾을 수 없음");


    }

    // USER 권한 테스트용 API
    @GetMapping("/user")
    public ResponseEntity<?> userApi(HttpServletRequest request) {
        log.info("user 접근 허용");
        return ResponseEntity.ok("send ok");
    }
}
