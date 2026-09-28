package vn.edu.hcmute.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import vn.edu.hcmute.jwt.user.User;
import vn.edu.hcmute.jwt.user.UserRepository;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(properties = {
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration,org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration,org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration",
        "security.jwt.secret-key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
})
@AutoConfigureMockMvc
class AuthenticationFlowTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @MockitoBean UserRepository repository;
    private final ConcurrentHashMap<String, User> users = new ConcurrentHashMap<>();
    private static final String SIGNUP = """
            {"fullName":"Nguyen Van A","email":"demo@example.com","password":"Password123!"}
            """;
    private static final String LOGIN = """
            {"email":"demo@example.com","password":"Password123!"}
            """;

    @BeforeEach void setup() {
        users.clear();
        when(repository.existsByEmail(anyString())).thenAnswer(i -> users.containsKey(i.getArgument(0)));
        when(repository.findByEmail(anyString())).thenAnswer(i -> Optional.ofNullable(users.get(i.getArgument(0))));
        when(repository.saveAndFlush(any(User.class))).thenAnswer(i -> {
            User user = i.getArgument(0);
            users.put(user.getEmail(), user);
            return user;
        });
        when(repository.findAll()).thenAnswer(i -> List.copyOf(users.values()));
    }

    @Test void signupLoginAndReadProtectedEndpoints() throws Exception {
        mvc.perform(post("/auth/signup").contentType("application/json").content(SIGNUP))
                .andExpect(status().isOk()).andExpect(jsonPath("password").doesNotExist());
        assertNotEquals("Password123!", users.get("demo@example.com").getPassword());
        String json = mvc.perform(post("/auth/login").contentType("application/json").content(LOGIN))
                .andExpect(status().isOk()).andExpect(jsonPath("expiresIn").value(3600000))
                .andReturn().getResponse().getContentAsString();
        String token = mapper.readTree(json).get("token").asText();
        mvc.perform(get("/users/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andExpect(jsonPath("email").value("demo@example.com"))
                .andExpect(jsonPath("password").doesNotExist());
        mvc.perform(get("/users/").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andExpect(jsonPath("$[0].password").doesNotExist());
    }

    @Test void rejectsMissingAndMalformedToken() throws Exception {
        mvc.perform(get("/users/me")).andExpect(status().isUnauthorized());
        mvc.perform(get("/users").header("Authorization", "Bearer broken"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("status").value(401));
    }

    @Test void rejectsDuplicateRegistrationAndWrongPassword() throws Exception {
        mvc.perform(post("/auth/signup").contentType("application/json").content(SIGNUP)).andExpect(status().isOk());
        mvc.perform(post("/auth/signup").contentType("application/json").content(SIGNUP)).andExpect(status().isConflict());
        mvc.perform(post("/auth/login").contentType("application/json").content(LOGIN.replace("Password123!", "wrong")))
                .andExpect(status().isUnauthorized());
    }

    @Test void rejectsInvalidInputAndServesLoginPage() throws Exception {
        mvc.perform(post("/auth/signup").contentType("application/json").content("{}"))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/login.html")).andExpect(status().isOk());
    }
}