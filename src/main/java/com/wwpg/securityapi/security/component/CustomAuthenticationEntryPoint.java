package com.wwpg.securityapi.security.component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
  // AuthenticationEntryPoint 는 인증되지않은사용자(로그인안된)가 보호된자원에 접근할 때 동작
  @Override
  public void commence(HttpServletRequest request
          , HttpServletResponse response
          , AuthenticationException authException) throws IOException, ServletException {
    System.out.println("===== CustomAuthenticationEntryPoint.commence() =====");
    System.out.println(request.getRequestURI());
    System.out.println(request.getMethod());
    System.out.println(request.getAttributeNames().toString());

    // 인가받은 페이지가 아닐때 React의 login페이지로 이동
    response.sendRedirect("http://localhost:5173/login");
  }
}
