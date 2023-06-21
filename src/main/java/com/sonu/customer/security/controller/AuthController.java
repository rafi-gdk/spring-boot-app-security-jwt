package com.sonu.customer.security.controller;

import com.sonu.customer.security.beans.AuthRequest;
import com.sonu.customer.security.jwt.JwtTokenUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/authenticate")
public class AuthController {
    
    private final JwtTokenUtil jwtTokenUtil;
    private final AuthenticationManager authenticationManager;

    @PostMapping
    public String getTokenForAuthenticatedUser(@RequestBody AuthRequest authRequest) {
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUserName(), authRequest.getPassword()));
        if (authentication.isAuthenticated()) {
            return jwtTokenUtil.generateToken(authRequest.getUserName());
        } else {
            throw new RuntimeException("Invalid user credentials");
        }
    }
}