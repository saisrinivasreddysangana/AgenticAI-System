package org.payroll.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class JwtResponse {
    private String token;
    private String refreshToken;
    private Long id;
    private String username;
    private String email;
    private String roles;
}