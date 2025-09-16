package com.wwpg.securityapi.security.service;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

  @Override
  public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

    System.out.println("=== CustomOAuth2UserService.loadUser() ===");

    OAuth2User oAuth2User = super.loadUser(userRequest);

    String registrationId = userRequest.getClientRegistration().getRegistrationId();

    Map<String, Object> attributes = oAuth2User.getAttributes();

    if ("naver".equals(registrationId)) {
      System.out.println("naver 로그인");
      Map<String, Object> response = (Map<String, Object>) attributes.get("response");
      String email = (String) response.get("email");
      if (email == null) {
        throw new OAuth2AuthenticationException("이메일이 없습니다.");
      }

      return new DefaultOAuth2User(
              Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
              response,
              "email"
      );
    }

    if ("kakao".equals(registrationId)) {
      System.out.println("kakao 로그인");

      // kakao_account 정보 추출
      Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");

      if (kakaoAccount == null) {
        throw new OAuth2AuthenticationException("kakao_account가 없습니다.");
      }

      String email = (String) kakaoAccount.get("email");
      if (email == null) {
        throw new OAuth2AuthenticationException("이메일이 없습니다.");
      }

      // profile 정보도 사용할 수 있음
      Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");
      String nickname = (String) profile.get("nickname");

      System.out.println(nickname);

      // 이메일 기준으로 유저 처리
      return new DefaultOAuth2User(
              Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
              kakaoAccount, // attributes로 kakaoAccount를 넣음
              "email"
      );
    }


    // 구글 로그인 일 때는 기본 클래스를 사용 (return)
    return oAuth2User;
  }
}
