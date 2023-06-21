package com.sonu.customer.security.beans;

import lombok.Data;

@Data
public class AuthRequest {

    private String userName;
    private String password;
}