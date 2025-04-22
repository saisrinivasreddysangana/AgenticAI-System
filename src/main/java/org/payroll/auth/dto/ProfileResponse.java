package org.payroll.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
public class ProfileResponse {
    private Long id;
    private String username;
    private String email;
    private List<String> roles;
}