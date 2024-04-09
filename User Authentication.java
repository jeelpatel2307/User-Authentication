@SpringBootApplication
public class UserAuthenticationApp {
    public static void main(String[] args) {
        SpringApplication.run(UserAuthenticationApp.class, args);
    }
}

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<UserDTO> register(@RequestBody RegisterRequest request) {
        User user = authService.register(request.getUsername(), request.getPassword());
        return ResponseEntity.ok(UserDTO.fromUser(user));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request.getUsername(), request.getPassword());
        return ResponseEntity.ok(response);
    }
}

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    public User register(String username, String password) {
        User user = new User(username, passwordEncoder.encode(password));
        return userRepository.save(user);
    }

    public AuthResponse login(String username, String password) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("Invalid username or password"));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new IllegalArgumentException("Invalid username or password");
        }

        String token = jwtService.generateToken(user);
        return new AuthResponse(token);
    }
}

@Entity
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }
}

@Data
public class RegisterRequest {
    private String username;
    private String password;
}

@Data
public class LoginRequest {
    private String username;
    private String password;
}

@Data
@AllArgsConstructor
public class AuthResponse {
    private String token;
}

@Data
public class UserDTO {
    private Long id;
    private String username;

    public static UserDTO fromUser(User user) {
        return new UserDTO(user.getId(), user.getUsername());
    }
}

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final JwtService jwtService;

    public SecurityConfig(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests()
            .antMatchers("/auth/**").permitAll()
            .anyRequest().authenticated()
            .and()
            .addFilterBefore(new JwtAuthFilter(jwtService), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

public class JwtService {
    private final String secret = "your_secret_key";

    public String generateToken(User user) {
        // Implement JWT token generation logic here
        // ...
        return "generated_token";
    }

    public boolean validateToken(String token) {
        // Implement JWT token validation logic here
        // ...
        return true;
    }
}

public class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtService jwtService;

    public JwtAuthFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String token = request.getHeader("Authorization");
        if (token != null && jwtService.validateToken(token)) {
            // Set the authenticated user in the security context
            // ...
        }
        filterChain.doFilter(request, response);
    }
}
