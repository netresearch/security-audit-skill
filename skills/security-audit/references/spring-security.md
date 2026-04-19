# Spring Security Patterns

Security patterns, common misconfigurations, and detection regexes for Spring Boot / Spring Security applications.

## Authentication & Authorization

### Spring Security Misconfiguration - permitAll Overreach

```java
// VULNERABLE: Over-permissive security configuration
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/**").permitAll()  // Entire API is open
                .requestMatchers("/admin/**").permitAll() // Admin panel unprotected
                .anyRequest().authenticated()
            );
        return http.build();
    }
}

// SECURE: Explicit, least-privilege path matching
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/user/**").hasRole("USER")
                .requestMatchers("/actuator/health").permitAll()
                .anyRequest().authenticated()
            );
        return http.build();
    }
}
```

**Detection regex:** `requestMatchers\s*\(\s*"\/(api|admin)\/\*\*"\s*\)\s*\.\s*permitAll\s*\(\s*\)`
**Severity:** error

### @PreAuthorize Bypass via Missing @EnableMethodSecurity

```java
// VULNERABLE: @PreAuthorize annotations have no effect without enablement
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    // This annotation is silently ignored!
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}

// Missing from configuration:
// @EnableMethodSecurity  <-- MUST be present on a @Configuration class

// SECURE: Enable method security explicitly
@Configuration
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class MethodSecurityConfig {
    // Method security annotations now enforced
}

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
```

**Detection regex:** `@PreAuthorize\s*\(`
**Severity:** warning

When `@PreAuthorize` is found, verify that `@EnableMethodSecurity` or the legacy `@EnableGlobalMethodSecurity` is declared on a `@Configuration` class. Without it, all method-level security annotations are silently ignored.

## Injection

### SpEL Injection

```java
// VULNERABLE: User input evaluated as SpEL expression
@RestController
public class SearchController {

    private final ExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/search")
    public Object search(@RequestParam String query) {
        // Attacker sends: T(java.lang.Runtime).getRuntime().exec('whoami')
        Expression exp = parser.parseExpression(query);
        return exp.getValue();
    }
}

// SECURE: Never parse untrusted input as SpEL; use SimpleEvaluationContext
@RestController
public class SearchController {

    private final ExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/search")
    public Object search(@RequestParam String filter) {
        // Use SimpleEvaluationContext to restrict available types and methods
        SimpleEvaluationContext context = SimpleEvaluationContext
            .forReadOnlyDataBinding()
            .withInstanceMethods()
            .build();

        // Only evaluate against a known root object, never raw user input
        SearchCriteria criteria = new SearchCriteria();
        Expression exp = parser.parseExpression("name");  // Fixed expression
        return exp.getValue(context, criteria);
    }
}
```

**Detection regex:** `parseExpression\s*\(\s*[a-zA-Z_]\w*\s*\)`
**Severity:** error

### Thymeleaf Server-Side Template Injection (SSTI)

```java
// VULNERABLE: Dynamic template name from user input
@Controller
public class PageController {

    @GetMapping("/page")
    public String renderPage(@RequestParam String template) {
        // Attacker sends: __${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
        return template;  // Thymeleaf evaluates this as a template expression
    }
}

// VULNERABLE: Unsafe fragment expression with user input
@Controller
public class FragmentController {

    @GetMapping("/fragment")
    public String renderFragment(@RequestParam String section, Model model) {
        return "page :: " + section;  // Attacker controls fragment expression
    }
}

// SECURE: Use an allowlist for template/fragment names
@Controller
public class PageController {

    private static final Set<String> ALLOWED_TEMPLATES = Set.of(
        "home", "about", "contact", "faq"
    );

    @GetMapping("/page")
    public String renderPage(@RequestParam String template) {
        if (!ALLOWED_TEMPLATES.contains(template)) {
            return "error/404";
        }
        return template;
    }
}
```

**Detection regex:** `return\s+(?:request|param|input|query|\w+)\s*;[\s\S]{0,5}$|return\s+"[^"]*"\s*\+\s*(?:request|param|input|\w+)`
**Severity:** error

### Jackson Deserialization - Polymorphic Typing

```java
// VULNERABLE: Default typing enabled globally
@Configuration
public class JacksonConfig {

    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        // DANGEROUS: allows attacker to specify arbitrary class instantiation
        mapper.enableDefaultTyping();
        // Also dangerous:
        // mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        // mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
        return mapper;
    }
}

// SECURE: Avoid default typing; use explicit type information
@Configuration
public class JacksonConfig {

    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        // Do NOT enable default typing
        // Use @JsonTypeInfo on specific classes where polymorphism is needed
        return mapper;
    }
}

// SECURE: If polymorphism is required, use allowlist-based typing
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = EmailNotification.class, name = "email"),
    @JsonSubTypes.Type(value = SmsNotification.class, name = "sms")
})
public abstract class Notification {
    // Only explicitly listed subtypes are allowed
}
```

**Detection regex:** `enableDefaultTyping\s*\(|activateDefaultTyping\s*\(`
**Severity:** error

## Security Misconfiguration

### Actuator Endpoint Exposure

```yaml
# VULNERABLE: application.yml - all actuator endpoints exposed without auth
management:
  endpoints:
    web:
      exposure:
        include: "*"
  endpoint:
    env:
      show-values: ALWAYS
    configprops:
      show-values: ALWAYS

# This exposes: /actuator/env (secrets), /actuator/configprops, /actuator/heapdump,
# /actuator/threaddump, /actuator/jolokia, /actuator/beans, /actuator/mappings

# SECURE: Only expose health and info; secure the rest
management:
  endpoints:
    web:
      exposure:
        include: health,info,prometheus
  endpoint:
    health:
      show-details: when-authorized
    env:
      show-values: NEVER
    configprops:
      show-values: NEVER
```

```java
// SECURE: Require admin role for sensitive actuator endpoints
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                .requestMatchers("/actuator/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            );
        return http.build();
    }
}
```

**Detection regex:** `include\s*:\s*["']?\*["']?|exposure\.include\s*=\s*\*`
**Severity:** error

### CSRF Configuration - Unsafe Disabling

```java
// VULNERABLE: CSRF protection disabled entirely
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())  // Disables CSRF for all endpoints
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return http.build();
    }
}

// SECURE: Disable CSRF only for stateless API endpoints, keep for browser sessions
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")
            .csrf(csrf -> csrf.disable())  // OK for stateless JWT API
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain webFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .csrfTokenRequestHandler(new XorCsrfTokenRequestAttributeHandler()))
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults());
        return http.build();
    }
}
```

**Detection regex:** `csrf\s*\(\s*(?:csrf|c)\s*->\s*(?:csrf|c)\.disable\s*\(\s*\)\s*\)|\.csrf\(\)\.disable\(\)`
**Severity:** warning

When CSRF is disabled, verify the endpoint chain is stateless (JWT/OAuth2 bearer tokens). CSRF disabling for session-based endpoints is a critical vulnerability.

### Mass Assignment via @ModelAttribute

```java
// VULNERABLE: Binding all request parameters to entity
@Controller
public class UserController {

    @PostMapping("/users/update")
    public String updateProfile(@ModelAttribute User user) {
        // Attacker can submit: role=ADMIN&enabled=true&id=1
        userRepository.save(user);
        return "redirect:/profile";
    }
}

// Entity without binding restrictions
@Entity
public class User {
    @Id private Long id;
    private String name;
    private String email;
    private String role;      // Attacker can escalate privileges
    private boolean enabled;  // Attacker can re-enable disabled accounts
}

// SECURE: Use a DTO with explicit fields
public record UserUpdateDto(
    @NotBlank @Size(max = 100) String name,
    @Email String email
) {}

// Form-binding variant (replaces the @ModelAttribute example above).
// Keeps the Controller-returns-view-name shape so it is a drop-in
// mitigation for the mass-assignment bug, not a different feature.
@Controller
public class UserController {

    @PostMapping("/users/update")
    public String updateProfile(@Valid @ModelAttribute UserUpdateDto dto,
                                Authentication auth) {
        User user = userRepository.findByUsername(auth.getName())
            .orElseThrow();
        user.setName(dto.name());
        user.setEmail(dto.email());
        // role and enabled are never exposed to user input
        userRepository.save(user);
        return "redirect:/profile";
    }
}

// REST variant — same allowlist DTO, different response style.
@RestController
public class UserApiController {

    @PostMapping("/api/users/update")
    public ResponseEntity<Void> updateProfile(@Valid @RequestBody UserUpdateDto dto,
                                              Authentication auth) {
        User user = userRepository.findByUsername(auth.getName())
            .orElseThrow();
        user.setName(dto.name());
        user.setEmail(dto.email());
        userRepository.save(user);
        return ResponseEntity.noContent().build();
    }
}

// ALTERNATIVE: Use @InitBinder to restrict bound fields
@Controller
public class UserController {

    @InitBinder
    public void initBinder(WebDataBinder binder) {
        binder.setAllowedFields("name", "email");
    }
}
```

**Detection regex:** `@ModelAttribute\s+(?!.*Dto|.*Request|.*Form|.*Command)\w+\s+\w+`
**Severity:** warning

### RestTemplate / WebClient SSRF

```java
// VULNERABLE: User-controlled URL passed to RestTemplate
@RestController
public class ProxyController {

    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/fetch")
    public ResponseEntity<String> fetch(@RequestParam String url) {
        // Attacker sends: url=http://169.254.169.254/latest/meta-data/
        // or url=http://localhost:8080/actuator/env
        String result = restTemplate.getForObject(url, String.class);
        return ResponseEntity.ok(result);
    }
}

// SECURE: Validate and restrict target URLs
@RestController
public class ProxyController {

    private final RestTemplate restTemplate;
    private static final Set<String> ALLOWED_HOSTS = Set.of(
        "api.trusted-service.com",
        "cdn.trusted-service.com"
    );

    @GetMapping("/fetch")
    public ResponseEntity<String> fetch(@RequestParam String url) {
        URI uri = URI.create(url);

        // Validate scheme
        if (!"https".equals(uri.getScheme())) {
            return ResponseEntity.badRequest().body("Only HTTPS allowed");
        }

        // Validate host against allowlist
        if (!ALLOWED_HOSTS.contains(uri.getHost())) {
            return ResponseEntity.badRequest().body("Host not allowed");
        }

        // Block private/internal IPs
        InetAddress address = InetAddress.getByName(uri.getHost());
        if (address.isLoopbackAddress() || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()) {
            return ResponseEntity.badRequest().body("Internal addresses not allowed");
        }

        String result = restTemplate.getForObject(uri, String.class);
        return ResponseEntity.ok(result);
    }
}
```

**Detection regex:** `(?:restTemplate|webClient|RestTemplate|WebClient)[\s\S]{0,60}(?:getForObject|getForEntity|exchange|retrieve|post|get|put|delete)\s*\(\s*(?!")[^)]*(?:request|param|input|url|uri|href|link|endpoint)`
**Severity:** error

## Data Exposure

### Sensitive Data in Spring Responses

```java
// VULNERABLE: Returning JPA entity directly — exposes all fields
@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/{id}")
    public User getUser(@PathVariable Long id) {
        // Returns: {"id":1,"name":"Alice","password":"$2a$10$...","ssn":"123-45-6789",...}
        return userRepository.findById(id).orElseThrow();
    }
}

// SECURE: Use a response DTO with explicit fields
public record UserResponse(Long id, String name, String email, String role) {

    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getName(),
                                user.getEmail(), user.getRole());
    }
}

@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/{id}")
    public UserResponse getUser(@PathVariable Long id) {
        User user = userRepository.findById(id).orElseThrow();
        return UserResponse.from(user);
    }
}

// ALTERNATIVE: Use @JsonIgnore on sensitive fields (less recommended)
@Entity
public class User {
    @Id private Long id;
    private String name;
    @JsonIgnore private String password;
    @JsonIgnore private String ssn;
}
```

**Detection regex:** `@GetMapping[\s\S]{0,200}return\s+\w+Repository\.find`
**Severity:** warning

## Detection Patterns for Spring

```java
// Grep patterns for Spring security issues:
String[] springPatterns = {
    "permitAll\\(\\)",                            // Verify scope of permitAll
    "csrf.*disable",                              // CSRF disabled
    "enableDefaultTyping",                        // Jackson unsafe deserialization
    "parseExpression\\(",                         // SpEL evaluation
    "include.*\\*",                               // Actuator wildcard exposure
    "@ModelAttribute\\s+(?!.*Dto)",               // Mass assignment risk
    "restTemplate.*getForObject.*\\$",            // SSRF via RestTemplate
    "@PreAuthorize",                              // Verify @EnableMethodSecurity present
    "return.*Repository\\.find",                  // Entity exposure in response
    "new ObjectInputStream",                      // Java deserialization
};
```

---

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SpEL injection (SA-SPRING-02) | Critical | Immediate | Medium |
| Actuator exposure (SA-SPRING-03) | Critical | Immediate | Low |
| Jackson default typing (SA-SPRING-08) | Critical | Immediate | Medium |
| RestTemplate SSRF (SA-SPRING-09) | Critical | Immediate | Medium |
| permitAll overreach (SA-SPRING-01) | High | 1 week | Low |
| Thymeleaf SSTI (SA-SPRING-06) | High | 1 week | Medium |
| CSRF disabled (SA-SPRING-04) | High | 1 week | Low |
| @PreAuthorize bypass (SA-SPRING-05) | High | 1 week | Low |
| Mass assignment (SA-SPRING-07) | Medium | 1 month | Medium |
| Entity exposure (SA-SPRING-10) | Medium | 1 month | Medium |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `java-security-features.md` — Java language-level patterns (deserialization, JNDI)
- `dotnet-security.md` — Comparison with ASP.NET Core patterns

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 3 — framework security references |
