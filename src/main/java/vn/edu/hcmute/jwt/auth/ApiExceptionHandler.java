package vn.edu.hcmute.jwt.auth;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice
public class ApiExceptionHandler {
    public record ApiError(int status, String message) { }

    @ExceptionHandler(AuthenticationException.class)
    ResponseEntity<ApiError> authentication(AuthenticationException exception) {
        int status = exception instanceof AccountStatusException ? 403 : 401;
        return ResponseEntity.status(status).body(new ApiError(status,
                status == 401 ? "Invalid email or password" : "Account unavailable"));
    }

    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<ApiError> invalidRequest(ResponseStatusException exception) {
        return ResponseEntity.status(exception.getStatusCode())
                .body(new ApiError(exception.getStatusCode().value(), exception.getReason()));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    ResponseEntity<ApiError> conflict() {
        return ResponseEntity.status(409).body(new ApiError(409, "User data conflicts with an existing record"));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<ApiError> malformedJson() {
        return ResponseEntity.badRequest().body(new ApiError(400, "Invalid JSON request"));
    }
}