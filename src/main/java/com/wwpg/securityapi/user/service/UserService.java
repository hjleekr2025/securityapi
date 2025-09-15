package com.wwpg.securityapi.user.service;

import com.wwpg.securityapi.user.dto.UserDTO;
import com.wwpg.securityapi.user.entity.User;
import com.wwpg.securityapi.user.entity.UserRole;
import com.wwpg.securityapi.user.repository.UserRepository;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Log4j2
@Service
@AllArgsConstructor
public class UserService {

    private final UserRepository userRepository; // JPARepository 상속으로 자동 Bean등록
    private final PasswordEncoder passwordEncoder;// SecurityConfig에 Bean등록

    public User create(UserDTO userDTO) {
        User user = User.builder()
                .email(userDTO.getEmail())
                .fromSocial(false)
                .password(userDTO.getPassword())
                .build();

        if (user == null || user.getEmail() == null) {
            throw new RuntimeException("Invalid arguments");

        }
        String email = user.getEmail();

        // 이미 가입된 이메일인지 확인하는 곳
        if (userRepository.existsByEmail(email)) {
            log.warn("Email already exist {}", email);
            throw new RuntimeException("Email already exist");
        }

        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);

        user.setRole(UserRole.USER);

        return userRepository.save(user);
    }


}
