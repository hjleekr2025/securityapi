package com.wwpg.securityapi.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
  // 인가된 페이지가 아닐때 이곳에서 처리합니다.
  @Override
  public void handle(HttpServletRequest request
          , HttpServletResponse response
          , AccessDeniedException accessDeniedException) throws IOException, ServletException {
    System.out.println("==== CustomAccessDeniedHandler.handle() ====");
    System.out.println("URI: " + request.getRequestURI());
    
    // 접근권한없음 안내페이지로 이동
    response.sendRedirect("http://localhost:5173/forbidden");
  }
}
