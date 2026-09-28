package vn.edu.hcmute.jwt.user;

import java.time.Instant;

public record UserResponse(Integer id, String fullName, String email, String images,
                           Instant createdAt, Instant updatedAt) {
    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getFullName(), user.getEmail(),
                user.getImages(), user.getCreatedAt(), user.getUpdatedAt());
    }
}