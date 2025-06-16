package com.infra_app.controller;

import com.infra_app.dto.*;
import com.infra_app.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody @Valid LoginRequest request,
                                               HttpServletResponse response){
        LoginResponse loginResponse = userService.login(request, response);
        return ResponseEntity.ok(loginResponse);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(@RequestHeader("Authorization") String token,HttpServletResponse response) {
        Long userId = userService.logout(token, response);
        return ResponseEntity.ok(ApiResponse.success("Logout successful", "LOGOUT_SUCCESS", 200, userId));
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(userService.register(request));
    }

    @PostMapping("/validate")
    public ResponseEntity<Boolean> validateToken(@RequestHeader("Authorization") String token) {
        boolean isValid = userService.validateToken(token);
        return ResponseEntity.ok(isValid);
    }

}