package creditdirect.clientmicrocervice.config;

import creditdirect.clientmicrocervice.entities.RoleType;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);



    @Autowired
    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil; // Initialize the jwtUtil field
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        final String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);

            try {
                Long userId = jwtUtil.extractUserId(token);
                String roleString = jwtUtil.extractRole(token);

                if (userId != null && roleString != null) {
                    RoleType userRole = RoleType.valueOf(roleString);
                    logger.info("JwtAuthenticationFilter: Filter execution for {}", request.getRequestURI());
                    logger.info("User Role: {} with id: {}", userRole, userId);

                    // Ensure that the authentication is successful before setting the SecurityContextHolder
                    Authentication authentication = new UsernamePasswordAuthenticationToken(
                            userId, null, jwtUtil.extractAuthorities(token));

                    if (authentication.isAuthenticated()) {
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        logger.info("Authentication success");
                    } else {
                        logger.error("Authentication failed");
                    }
                }

            } catch (ExpiredJwtException e) {
                logger.error("JWT token has expired", e);
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token has expired", e);
            } catch (UnsupportedJwtException e) {
                logger.error("Unsupported JWT token", e);
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unsupported JWT token", e);
            } catch (Exception e) {
                logger.error("Error processing JWT token", e);
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired token", e);
            }
        }

        filterChain.doFilter(request, response);
    }
}