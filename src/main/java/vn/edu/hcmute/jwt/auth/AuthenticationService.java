package vn.edu.hcmute.jwt.auth;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import vn.edu.hcmute.jwt.user.User;
import vn.edu.hcmute.jwt.user.UserRepository;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

@Service
public class AuthenticationService {
    private final UserRepository repository;
    private final PasswordEncoder encoder;
    private final AuthenticationManager authenticationManager;

    public AuthenticationService(UserRepository repository, PasswordEncoder encoder,
                                 AuthenticationManager authenticationManager) {
        this.repository = repository;
        this.encoder = encoder;
        this.authenticationManager = authenticationManager;
    }

    @Transactional
    public User signup(String fullName, String email, String password) {
        String normalizedEmail = validateCredentials(email, password);
        if (fullName == null || fullName.isBlank() || fullName.strip().length() > 50 || password.length() < 8) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Full name must contain 1-50 characters; password must contain at least 8 characters");
        }
        if (repository.existsByEmail(normalizedEmail)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already registered");
        }
        return repository.saveAndFlush(new User(fullName.strip(), normalizedEmail, encoder.encode(password)));
    }

    public User authenticate(String email, String password) {
        String normalizedEmail = validateCredentials(email, password);
        return (User) authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(normalizedEmail, password)).getPrincipal();
    }

    private String validateCredentials(String email, String password) {
        if (email == null || email.strip().length() > 100
                || !email.strip().matches("[^\\s@]+@[^\\s@]+\\.[^\\s@]+")
                || password == null || password.isBlank()
                || password.getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Provide a valid email and a password of at most 72 UTF-8 bytes");
        }
        return email.strip().toLowerCase(Locale.ROOT);
    }
}