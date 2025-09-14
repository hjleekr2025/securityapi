package com.wwpg.securityapi.user.repository;

import com.wwpg.securityapi.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


// JpaRepository를 상속한 Repository 인터페이스는 자동으로 @Repository 빈으로 등록된다.
public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByEmail(String email);
    Boolean existsByEmail(String email);
}
