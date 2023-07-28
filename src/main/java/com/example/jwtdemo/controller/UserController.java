package com.example.jwtdemo.controller;

import com.example.jwtdemo.config.jwt.JwtAuthenticationProvider;
import com.example.jwtdemo.entity.User;
import com.example.jwtdemo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RequiredArgsConstructor
@RequestMapping(path = "/api/user/")
@RestController
public class UserController {
    private final PasswordEncoder passwordEncoder;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;
    private final UserRepository userRepository;

    // 회원가입
    @PostMapping("/join")
    public Long join(@RequestBody Map<String, String> user) {
        return userRepository.save(User.builder()
                .userId(user.get("user_id"))
                .password(passwordEncoder.encode(user.get("user_pwd")))
                .roles(Collections.singletonList("ROLE_USER")) // 최초 가입시 USER 로 설정
                .build()).getId();
    }

    // 로그인
    @PostMapping("/login")
    public String login(@RequestBody Map<String, String> user) {
        User member = userRepository.findByUserId(user.get("user_id"))
                .orElseThrow(() -> new IllegalArgumentException("가입되지 않은 계정 입니다."));
        if (!passwordEncoder.matches(user.get("user_pwd"), member.getPassword())) {
            throw new IllegalArgumentException("잘못된 비밀번호입니다.");
        }
        return jwtAuthenticationProvider.createToken(member.getUsername(), member.getRoles());
    }
}
