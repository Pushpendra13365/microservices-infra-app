package com.infra_app.service.serviceImpl;

import com.infra_app.dto.*;
import com.infra_app.exception.*;
import com.infra_app.model.*;
import com.infra_app.repository.*;
import com.infra_app.util.JwtUtil;
import com.infra_app.service.UserService;
import com.infra_app.util.CookieUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository userRepo;
    private final UserTokenRepository tokenRepo;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public LoginResponse login(LoginRequest request, HttpServletResponse response){

        try {
            User user = userRepo.findByUsername(request.getUserName())
                    .orElseThrow(() -> new BadCredentialsException("Invalid username or password"));

            if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                throw new BadCredentialsException("Invalid username or password");
            }

            List<SimpleGrantedAuthority> authorities = List.of(
                    new SimpleGrantedAuthority(user.getRole().name()));

            String accessToken = jwtUtil.generateAccessToken(user.getUsername(), authorities);

            tokenRepo.invalidateAllUserTokens(user.getId());
            tokenRepo.saveAll(List.of(
                    UserToken.builder()
                            .user(user)
                            .token(accessToken)
                            .tokenType(TokenType.ACCESS)
                            .expiryTime(LocalDateTime.now().plusHours(3))
                            .build()));
            CookieUtil.addJwtCookie(response, accessToken);

            log.info("User '{}' logged in successfully", user.getUsername());
            return new LoginResponse(accessToken , user.getId());
        } catch (BadCredentialsException e) {
            log.warn("Failed login attempt for user: {}", request.getUserName());
            throw new CustomUnauthorizedException("Invalid username or password");
        }
    }

    @Override
    @Transactional
    public Long logout(String token, HttpServletResponse response) {
        if (token == null || !token.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Invalid authorization header");
        }

        String token1 = token.substring(7);

        if (token1.isEmpty()) {
            throw new CustomUnauthorizedException("Token must not be empty");
        }

        Long userId = tokenRepo.findUserIdByToken(token1)
                .orElseThrow(() -> new CustomUnauthorizedException("Invalid token"));

        int updated = tokenRepo.invalidateToken(token1);

        if (updated == 0) {
            log.warn("Token not found or already invalidated: {}", token);
            throw new CustomUnauthorizedException("Token not found or already invalidated");
        }

        CookieUtil.clearJwtCookie(response);

        log.info("Successfully logged out, token invalidated: {}", token);
        return userId;
    }

    @Override
    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        if (userRepo.findByUsername(request.getUsername()).isPresent()) {
            throw new UserAlreadyExistsException("Username already exists: " + request.getUsername());
        }

        Role role;
        try {
            role = Role.valueOf(request.getRole().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new InvalidRoleException("Invalid role specified: " + request.getRole());
        }

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(role)
                .build();

        userRepo.save(user);

        log.info("New user registered: {}", user.getUsername());
        return new RegisterResponse("User registered successfully", user.getUsername());
    }

    @Override
    public boolean validateToken(String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            return false;
        }

        String jwtToken = token.substring(7);

        if (!jwtUtil.validateJwtToken(jwtToken)) {
            return false;
        }

        return tokenRepo.findByTokenAndBlacklistedFalse(jwtToken)
                .map(t -> !t.getExpiryTime().isBefore(LocalDateTime.now()))
                .orElse(false);
    }

}