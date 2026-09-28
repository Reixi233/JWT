package vn.edu.hcmute.jwt.auth;

import org.springframework.web.bind.annotation.*;
import vn.edu.hcmute.jwt.security.JwtService;
import vn.edu.hcmute.jwt.user.UserResponse;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    private final JwtService jwtService;

    public AuthenticationController(AuthenticationService authenticationService, JwtService jwtService) {
        this.authenticationService = authenticationService;
        this.jwtService = jwtService;
    }

    public record RegisterUserModel(String email, String password, String fullName) { }
    public record LoginUserModel(String email, String password) { }
    public record LoginResponse(String token, long expiresIn) { }

    @PostMapping("/signup")
    public UserResponse register(@RequestBody RegisterUserModel request) {
        return UserResponse.from(authenticationService.signup(request.fullName(), request.email(), request.password()));
    }

    @PostMapping("/login")
    public LoginResponse authenticate(@RequestBody LoginUserModel request) {
        var user = authenticationService.authenticate(request.email(), request.password());
        return new LoginResponse(jwtService.generateToken(user), jwtService.getExpirationTime());
    }
}