package com.example.auth.security;

import com.example.auth.entity.Permission;
import com.example.auth.entity.Role;
import com.example.auth.entity.User;
import com.example.auth.service.AuthService;
import com.example.auth.service.TokenService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;

/**
 * JWT Authentication Filter that validates JWT tokens and sets up Spring Security context.
 * Extends OncePerRequestFilter to ensure it's executed once per request.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final TokenService tokenService;
    private final AuthService authService;

    @Autowired
    public JwtAuthenticationFilter(TokenService tokenService, AuthService authService) {
        this.tokenService = tokenService;
        this.authService = authService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                   HttpServletResponse response, 
                                   FilterChain filterChain) throws ServletException, IOException {
        
        try {
            // Debug: expose request path for diagnostics (only meaningful in development)
            if (logger.isDebugEnabled()) {
                response.setHeader("X-Debug-Path", request.getRequestURI());
            }
            // Extract JWT token from Authorization header
            String jwt = extractJwtFromRequest(request);
            
            if (jwt != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // Validate token and get user
                Optional<User> userOpt = authService.validateTokenAndGetUser(jwt);
                
                if (userOpt.isPresent()) {
                    User user = userOpt.get();
                    
                    // Create authentication token with authorities
                    UsernamePasswordAuthenticationToken authToken = createAuthenticationToken(user, jwt, request);
                    
                    // Set authentication in security context
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    if (logger.isDebugEnabled()) {
                        response.setHeader("X-Debug-Auth-User", user.getUsername());
                        String auths = authToken.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .reduce((a,b) -> a + "," + b)
                                .orElse("");
                        response.setHeader("X-Debug-Authorities", auths);
                    }
                    
                    logger.debug("JWT authentication successful for user: {}", user.getUsername());
                } else {
                    logger.debug("JWT authentication failed - invalid token or user");
                }
            }
        } catch (Exception e) {
            logger.error("JWT authentication error: {}", e.getMessage());
            // Clear security context on error
            SecurityContextHolder.clearContext();
        }

        // Continue filter chain
        filterChain.doFilter(request, response);
    }

    /**
     * Extract JWT token from Authorization header.
     */
    private String extractJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        
        if (bearerToken != null && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }

    /**
     * Create authentication token with user authorities.
     */
    private UsernamePasswordAuthenticationToken createAuthenticationToken(User user, String jwt, HttpServletRequest request) {
        // Get authorities from token claims (more efficient than database lookup)
        List<GrantedAuthority> authorities = getAuthoritiesFromToken(jwt);
        
        // If token doesn't have authorities, fall back to user entity
        if (authorities.isEmpty()) {
            authorities = getAuthoritiesFromUser(user);
        }
        
        // Create authentication token
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                user.getUsername(), // principal
                null,              // credentials (not needed for JWT)
                authorities        // authorities
        );
        
        // Set authentication details
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        
        return authToken;
    }

    /**
     * Extract authorities from JWT token claims.
     */
    private List<GrantedAuthority> getAuthoritiesFromToken(String jwt) {
        try {
            Optional<Claims> claimsOpt = tokenService.parseClaimsFromAccessToken(jwt);
            if (claimsOpt.isEmpty()) {
                return new ArrayList<>();
            }
            
            Claims claims = claimsOpt.get();
            List<GrantedAuthority> authorities = new ArrayList<>();
            
            // Add roles as authorities
            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) claims.get("roles");
            if (roles != null) {
                for (String role : roles) {
                    authorities.add(new SimpleGrantedAuthority(role));
                }
            }
            
            // Add permissions as authorities
            @SuppressWarnings("unchecked")
            List<String> permissions = (List<String>) claims.get("permissions");
            if (permissions != null) {
                for (String permission : permissions) {
                    authorities.add(new SimpleGrantedAuthority(permission));
                }
            }
            
            return authorities;
        } catch (Exception e) {
            logger.warn("Failed to extract authorities from token: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Extract authorities from user entity (fallback method).
     */
    private List<GrantedAuthority> getAuthoritiesFromUser(User user) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        
        // Add roles
        for (Role role : user.getRoles()) {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        }
        
        // Add permissions
        for (Permission permission : user.getAllPermissions()) {
            authorities.add(new SimpleGrantedAuthority(permission.getName()));
        }
        
        return authorities;
    }

    /**
     * Determine if the filter should be applied to this request.
     * Skip filtering for public endpoints.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
     // Use servletPath to ignore the context-path (e.g., '/api') when matching
     String path = request.getServletPath();

     // Skip JWT filtering for public endpoints
     return path.equals("/auth/login") ||
         path.equals("/auth/refresh") ||
         path.equals("/auth/logout") ||
         path.equals("/auth/health") ||
         path.startsWith("/actuator/health") ||
         path.startsWith("/actuator/info") ||
         path.startsWith("/actuator/prometheus") ||
         path.startsWith("/v3/api-docs") ||
         path.startsWith("/swagger-ui");
    }
}