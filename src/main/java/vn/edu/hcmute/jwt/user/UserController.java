package vn.edu.hcmute.jwt.user;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {
    private final UserRepository repository;

    public UserController(UserRepository repository) { this.repository = repository; }

    @GetMapping("/me")
    public UserResponse me(@AuthenticationPrincipal User user) { return UserResponse.from(user); }

    @GetMapping({"", "/"})
    public List<UserResponse> allUsers() {
        return repository.findAll().stream().map(UserResponse::from).toList();
    }
}