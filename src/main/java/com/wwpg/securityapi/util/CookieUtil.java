package com.wwpg.securityapi.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;

@Component
public class CookieUtil {
    // 쿠키 가져오기
    public String getCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) {
            return null;
        }

        Optional<Cookie> cookie = Arrays.stream(request.getCookies())
                .filter(c -> c.getName().equals(name))
                .findFirst();

        return cookie.map(Cookie::getValue).orElse(null);
    }

    // 쿠키 생성
    public void createCookie(HttpServletResponse response, String name, String value, int maxAgeInSeconds) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);   // 쿠키를 HttpOnly로 설정하면 JavaScript로 접근이 불가능하다
        //cookie.setSecure(true);   // HTTPS에서만 전송
        cookie.setPath("/");        // 전체 경로에서 사용 가능
        cookie.setMaxAge(maxAgeInSeconds);  // 쿠키 만료 시간 (초 단위)
        response.addCookie(cookie);
    }

    // 쿠키 삭제
    public void deleteCookie(HttpServletResponse response, String name) {
        Cookie cookie = new Cookie(name, null);
        cookie.setPath("/");
        cookie.setMaxAge(0);        // 즉시 만료
        response.addCookie(cookie);
    }
}
