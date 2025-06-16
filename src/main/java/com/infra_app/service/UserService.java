package com.infra_app.service;

import com.infra_app.dto.*;
import javax.security.auth.login.AccountLockedException;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

public interface UserService {
    LoginResponse login(LoginRequest request, HttpServletResponse response);
    Long logout(String token, HttpServletResponse response);
    RegisterResponse register(RegisterRequest request);
    public boolean validateToken(String token);
}
