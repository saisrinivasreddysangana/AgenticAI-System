package org.payroll.auth.controller;

import jakarta.validation.Valid;
import org.payroll.auth.dto.*;
import org.payroll.auth.entity.RefreshToken;
import org.payroll.auth.entity.Role;
import org.payroll.auth.entity.User;
import org.payroll.auth.enums.RoleEnum;
import org.payroll.auth.exception.RoleNotFoundException;
import org.payroll.auth.repository.RoleRepository;
import org.payroll.auth.repository.UserRepository;
import org.payroll.auth.security.JwtTokenProvider;
import org.payroll.auth.security.UserDetailsImpl;
import org.payroll.auth.service.RefreshTokenService;
import org.payroll.auth.security.UserDetailsServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final UserDetailsServiceImpl userDetailsService;

    public AuthController(
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder encoder,
            JwtTokenProvider jwtTokenProvider,
            RefreshTokenService refreshTokenService,
            UserDetailsServiceImpl userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenService = refreshTokenService;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        logger.info("Processing login request for email: {}", loginRequest.getEmail());
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

            String jwt = jwtTokenProvider.generateToken(authentication);
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

            logger.info("Successfully authenticated user: {}, JWT: {}, Refresh Token: {}",
                    userDetails.getUsername(), jwt, refreshToken.getToken());
            return ResponseEntity.ok(new JwtResponse(
                    jwt,
                    refreshToken.getToken(),
                    userDetails.getId(),
                    userDetails.getUsername(),
                    userDetails.getEmail(),
                    userDetails.getAuthorities().toString()));
        } catch (AuthenticationException e) {
            logger.error("Authentication failed for email: {}. Reason: {}", loginRequest.getEmail(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid credentials"));
        } catch (DataIntegrityViolationException e) {
            logger.error("Database constraint violation during login for email: {}. Reason: {}", loginRequest.getEmail(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Failed to create refresh token due to a database issue"));
        } catch (Exception e) {
            logger.error("Unexpected error during login for email: {}. Reason: {}", loginRequest.getEmail(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Internal server error, please try again later"));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest, BindingResult result) {
        if (result.hasErrors()) {
            String errors = result.getFieldErrors().stream()
                    .map(error -> error.getDefaultMessage())
                    .collect(Collectors.joining(", "));
            return ResponseEntity.badRequest().body(new MessageResponse("Validation errors: " + errors));
        }

        if (userRepository.existsByUsernameOrEmail(signUpRequest.getUsername(), signUpRequest.getEmail())) {
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error: Username or email is already taken!"));
        }

        User user = User.builder()
                .username(signUpRequest.getUsername())
                .email(signUpRequest.getEmail())
                .password(encoder.encode(signUpRequest.getPassword()))
                .active(true)
                .build();

        Set<String> strRoles = signUpRequest.getRoles();
        Set<Role> roles = new HashSet<>();
        if (strRoles == null || strRoles.isEmpty()) {
            roles.add(getRole(RoleEnum.USER));
        } else {
            roles.addAll(strRoles.stream()
                    .map(role -> {
                        try {
                            return getRole(RoleEnum.valueOf(role.toUpperCase()));
                        } catch (IllegalArgumentException e) {
                            throw new IllegalArgumentException("Invalid role: " + role);
                        }
                    })
                    .collect(Collectors.toSet()));
        }

        user.setRoles(roles);
        userRepository.save(user);

        logger.info("Successfully registered user: {}", signUpRequest.getUsername());
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
        String requestToken = request.getRefreshToken();
        logger.info("Processing refresh token request");

        return refreshTokenService.findByToken(requestToken)
                .map(token -> {
                    if (refreshTokenService.isExpired(token)) {
                        refreshTokenService.deleteByUserId(token.getUser().getId());
                        logger.warn("Refresh token expired for user ID: {}", token.getUser().getId());
                        return ResponseEntity.badRequest()
                                .body(new MessageResponse("Error: Refresh token was expired. Please login again."));
                    }

                    String newJwt = jwtTokenProvider.generateTokenFromUsername(token.getUser().getUsername());
                    logger.info("Generated new JWT for user: {}", token.getUser().getUsername());
                    return ResponseEntity.ok(new TokenRefreshResponse(newJwt, requestToken, "Bearer"));
                })
                .orElseGet(() -> {
                    logger.error("Refresh token not found: {}", requestToken);
                    return ResponseEntity.badRequest()
                            .body(new MessageResponse("Error: Refresh token not found."));
                });
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getProfile(@RequestHeader("Authorization") String authHeader) {
        logger.info("Processing profile request");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            logger.error("Missing or invalid Authorization header");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse("Missing or invalid Authorization header"));
        }

        String token = authHeader.substring(7);
        if (!jwtTokenProvider.validateToken(token)) {
            logger.error("Invalid or expired token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid or expired token"));
        }

        try{
        String username = jwtTokenProvider.getUsernameFromToken(token);
        UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(username);

        logger.info("Retrieved profile for user: {}", username);
        return ResponseEntity.ok(new ProfileResponse(
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList())
        ));
    }catch (Exception e) {
            logger.error("Error retrieving profile: {}",  e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Error retrieving profile"));
        }
    }

    private Role getRole(RoleEnum roleEnum) {
        return roleRepository.findByName(roleEnum)
                .orElseThrow(() -> new RoleNotFoundException("Role " + roleEnum + " not found"));
    }
}