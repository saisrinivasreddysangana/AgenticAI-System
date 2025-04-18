package org.payroll.auth.security;

import jakarta.servlet.http.*;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException)
            throws IOException, ServletException {

        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        ServletOutputStream out = response.getOutputStream();
        out.println("{\"error\": \"Unauthorized access\"}");
        out.flush();
    }
}
