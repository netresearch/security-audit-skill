# NestJS Security Patterns

Security patterns, common misconfigurations, and detection regexes for NestJS applications. NestJS provides a structured, decorator-driven architecture on top of Express (or Fastify). Its guard, pipe, interceptor, and filter system offers powerful security primitives, but misconfiguration of these layers -- especially ordering, precedence, and the `@Public()` escape hatch -- is a frequent source of vulnerabilities.

---

## Guard Ordering and Precedence

### SA-NEST-01: Guard Ordering and Precedence

NestJS guards execute in a specific order: global guards first, then controller-level, then method-level. If guards are applied at the wrong level or in the wrong order, authorization checks may be skipped. Combining `@UseGuards()` with global guards can create unexpected precedence issues.

```typescript
// VULNERABLE: Auth guard only on some methods — others are unprotected
@Controller('users')
export class UsersController {
  @Get()
  findAll() {
    // NO guard — any anonymous user can list all users
    return this.usersService.findAll();
  }

  @UseGuards(AuthGuard)
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.usersService.remove(id);
  }
}

// VULNERABLE: RolesGuard before AuthGuard — roles checked without auth
@Controller('admin')
@UseGuards(RolesGuard, AuthGuard)
export class AdminController {
  @Get('dashboard')
  getDashboard() {
    // RolesGuard runs first, but user is not authenticated yet!
    return this.adminService.getDashboard();
  }
}

// VULNERABLE: Global guard registered in wrong module
@Module({
  providers: [
    // This only applies to THIS module, not globally
    { provide: APP_GUARD, useClass: AuthGuard },
  ],
})
export class UsersModule {}
```

```typescript
// SECURE: Global auth guard in AppModule with correct ordering
@Module({
  providers: [
    // Global guard — applies to ALL routes
    { provide: APP_GUARD, useClass: AuthGuard },
    { provide: APP_GUARD, useClass: RolesGuard }, // Runs after AuthGuard
  ],
})
export class AppModule {}

// SECURE: Controller-level guard with correct ordering
@Controller('admin')
@UseGuards(AuthGuard, RolesGuard) // Auth FIRST, then roles
@Roles('admin')
export class AdminController {
  @Get('dashboard')
  getDashboard() {
    return this.adminService.getDashboard();
  }
}

// SECURE: Guard on every route via controller decorator
@Controller('users')
@UseGuards(AuthGuard)
export class UsersController {
  @Get()
  findAll() {
    // Protected by controller-level guard
    return this.usersService.findAll();
  }

  @Delete(':id')
  @Roles('admin')
  @UseGuards(RolesGuard) // Additional guard for this route
  remove(@Param('id') id: string) {
    return this.usersService.remove(id);
  }
}
```

**Detection regex:** `@UseGuards\s*\(\s*RolesGuard\s*,\s*AuthGuard\s*\)|@Controller\s*\([^)]*\)\s*\nexport\s+class\s+\w+\s*\{(?![\s\S]*?@UseGuards)`
**Severity:** error

---

## DTO Validation

### SA-NEST-02: DTO Validation (class-validator)

NestJS relies on `class-validator` and `class-transformer` with `ValidationPipe` to validate incoming data. Without the global validation pipe or with `whitelist: false`, attackers can send additional fields that map to entity properties (mass assignment).

```typescript
// VULNERABLE: No ValidationPipe — DTOs are not validated
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  // Missing: app.useGlobalPipes(new ValidationPipe());
  await app.listen(3000);
}

// VULNERABLE: DTO without validation decorators
export class CreateUserDto {
  name: string;       // No @IsString(), no @IsNotEmpty()
  email: string;      // No @IsEmail()
  role: string;       // Sensitive field — should not be in DTO
  isAdmin: boolean;   // Sensitive field — mass assignment!
}

// VULNERABLE: ValidationPipe without whitelist
app.useGlobalPipes(new ValidationPipe({
  whitelist: false,    // Extra properties are NOT stripped
  transform: true,
}));
```

```typescript
// SECURE: Global ValidationPipe with strict settings
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,           // Strip properties without decorators
    forbidNonWhitelisted: true, // Throw on unexpected properties
    transform: true,            // Auto-transform types
    disableErrorMessages: false,
  }));
  await app.listen(3000);
}

// SECURE: DTO with explicit validation — no sensitive fields
import { IsString, IsEmail, IsNotEmpty, MaxLength } from 'class-validator';

export class CreateUserDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  name: string;

  @IsEmail()
  email: string;

  // role and isAdmin are NOT in the DTO — set server-side
}

// SECURE: Service sets sensitive fields
@Injectable()
export class UsersService {
  async create(dto: CreateUserDto, currentUser: User) {
    const user = this.usersRepo.create({
      ...dto,
      role: 'user',       // Explicitly set server-side
      isAdmin: false,     // Explicitly set server-side
      createdBy: currentUser.id,
    });
    return this.usersRepo.save(user);
  }
}
```

**Detection regex:** `new\s+ValidationPipe\s*\(\s*\{[^}]*whitelist\s*:\s*false|class\s+\w+Dto\s*\{(?![\s\S]*?@Is)`
**Severity:** error

---

## Interceptor Data Transformation

### SA-NEST-03: Interceptor Data Leakage

Interceptors transform responses. Without explicit serialization (e.g., `ClassSerializerInterceptor` or custom transformations), entity objects with sensitive fields (passwords, tokens, internal IDs) may be returned directly to clients.

```typescript
// VULNERABLE: Entity returned directly — password hash exposed
@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  email: string;

  @Column()
  password: string;  // Hash exposed in API response!

  @Column()
  internalNotes: string;  // Internal data exposed!
}

@Controller('users')
export class UsersController {
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.usersService.findOne(id); // Returns full entity
  }
}
```

```typescript
// SECURE: Use @Exclude() and ClassSerializerInterceptor
import { Exclude, plainToInstance } from 'class-transformer';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  email: string;

  @Column()
  @Exclude()
  password: string;  // Excluded from serialization

  @Column()
  @Exclude()
  internalNotes: string;  // Excluded from serialization
}

// Enable globally in main.ts
app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)));

// Or use a response DTO
export class UserResponseDto {
  id: number;
  email: string;
  name: string;
  // password and internalNotes are simply not included
}

@Controller('users')
export class UsersController {
  @Get(':id')
  async findOne(@Param('id') id: string): Promise<UserResponseDto> {
    const user = await this.usersService.findOne(id);
    return plainToInstance(UserResponseDto, user, { excludeExtraneousValues: true });
  }
}
```

**Detection regex:** `@Column\s*\(\s*\)\s*\n\s*password\s*:|@Column\s*\(\s*\)\s*\n\s*(?:secret|token|hash|internal)`
**Severity:** warning

---

## Pipe Validation Bypass

### SA-NEST-04: Pipe Validation Bypass

`ParseIntPipe`, `ParseUUIDPipe`, and custom pipes validate individual parameters. Omitting these pipes on route parameters allows type confusion attacks, NoSQL injection via object parameters, and integer overflow.

```typescript
// VULNERABLE: No ParseIntPipe — id could be any string
@Controller('users')
export class UsersController {
  @Get(':id')
  findOne(@Param('id') id: string) {
    // id is unvalidated: could be "1 OR 1=1", NaN, or very long string
    return this.usersService.findOne(id);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    // MongoDB: id could be { $ne: null } if parsed from nested query
    return this.usersService.remove(id);
  }
}

// VULNERABLE: Query param without validation
@Controller('products')
export class ProductsController {
  @Get()
  findAll(@Query('page') page: string, @Query('limit') limit: string) {
    // page and limit are raw strings — could be negative, huge, or NaN
    return this.productsService.findAll(+page, +limit);
  }
}
```

```typescript
// SECURE: Built-in pipes for type safety
@Controller('users')
export class UsersController {
  @Get(':id')
  findOne(@Param('id', ParseUUIDPipe) id: string) {
    // Only valid UUIDs pass through
    return this.usersService.findOne(id);
  }

  @Delete(':id')
  remove(@Param('id', ParseIntPipe) id: number) {
    return this.usersService.remove(id);
  }
}

// SECURE: Custom validation pipe for query params
@Controller('products')
export class ProductsController {
  @Get()
  findAll(
    @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number,
    @Query('limit', new DefaultValuePipe(20), ParseIntPipe) limit: number,
  ) {
    const safePage = Math.max(1, page);
    const safeLimit = Math.min(100, Math.max(1, limit));
    return this.productsService.findAll(safePage, safeLimit);
  }
}
```

**Detection regex:** `@Param\s*\(\s*['"][^'"]+['"]\s*\)\s+\w+\s*:\s*string(?!\s*,)|@Query\s*\(\s*['"][^'"]+['"]\s*\)\s+\w+\s*:\s*string`
**Severity:** warning

---

## @Public Decorator Misuse

### SA-NEST-05: @Public Decorator Misuse

When a global `AuthGuard` is registered, the `@Public()` (or `@SkipAuth()`) decorator exempts specific routes. Misapplying this decorator to sensitive endpoints bypasses authentication entirely.

```typescript
// VULNERABLE: @Public on sensitive endpoints
@Controller('users')
export class UsersController {
  @Public()   // Authentication bypassed!
  @Get('profile')
  getProfile() {
    // This returns the "current user" but there is no current user
    return this.usersService.getProfile();
  }

  @Public()   // Authentication bypassed!
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.usersService.remove(id);
  }
}

// VULNERABLE: @Public on entire controller
@Public()
@Controller('admin')
export class AdminController {
  @Get('users')
  listUsers() { return this.adminService.listUsers(); }

  @Post('settings')
  updateSettings(@Body() dto: UpdateSettingsDto) {
    return this.adminService.updateSettings(dto);
  }
}
```

```typescript
// SECURE: @Public only on truly public endpoints
@Controller('users')
export class UsersController {
  @Public()
  @Get('register')
  showRegistrationForm() {
    return { message: 'Registration page' };
  }

  @Public()
  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  // No @Public — requires authentication
  @Get('profile')
  getProfile(@CurrentUser() user: User) {
    return this.usersService.getProfile(user.id);
  }

  @Roles('admin')
  @Delete(':id')
  remove(@Param('id', ParseUUIDPipe) id: string) {
    return this.usersService.remove(id);
  }
}
```

**Detection regex:** `@Public\s*\(\s*\)\s*\n\s*@(Delete|Put|Patch|Post)\s*\(|@Public\s*\(\s*\)\s*\n\s*@Controller`
**Severity:** error

---

## WebSocket Gateway Auth

### SA-NEST-06: WebSocket Gateway Authentication

NestJS WebSocket gateways (`@WebSocketGateway()`) do not inherit HTTP guards by default. Without explicit authentication in `handleConnection()` or a gateway-level guard, any client can connect and subscribe to events.

```typescript
// VULNERABLE: No authentication on WebSocket gateway
@WebSocketGateway()
export class EventsGateway {
  @SubscribeMessage('admin:data')
  handleAdminData(@MessageBody() data: any) {
    // Any client can subscribe to admin data!
    return this.adminService.getSensitiveData();
  }

  @SubscribeMessage('chat:message')
  handleMessage(@MessageBody() data: any, @ConnectedSocket() client: Socket) {
    // No auth — anonymous users can send messages as anyone
    this.server.emit('chat:message', { user: data.user, text: data.text });
  }
}

// VULNERABLE: afterInit but not handleConnection
@WebSocketGateway()
export class EventsGateway implements OnGatewayInit {
  afterInit(server: Server) {
    console.log('Gateway initialized');
    // This does NOT authenticate individual connections
  }
}
```

```typescript
// SECURE: Auth in handleConnection and message-level guards
@WebSocketGateway()
export class EventsGateway implements OnGatewayConnection {
  constructor(private authService: AuthService) {}

  async handleConnection(client: Socket) {
    try {
      const token = client.handshake.auth?.token
        || client.handshake.headers?.authorization?.split(' ')[1];
      if (!token) throw new Error('No token');

      const user = await this.authService.verifyToken(token);
      client.data.user = user; // Attach user to socket
    } catch (e) {
      client.emit('error', { message: 'Unauthorized' });
      client.disconnect();
    }
  }

  @UseGuards(WsAuthGuard)
  @SubscribeMessage('admin:data')
  handleAdminData(@ConnectedSocket() client: Socket) {
    if (client.data.user.role !== 'admin') {
      throw new WsException('Forbidden');
    }
    return this.adminService.getSensitiveData();
  }
}
```

**Detection regex:** `@WebSocketGateway\s*\([\s\S]*?\)[\s\S]*?export\s+class\s+\w+(?![\s\S]*?handleConnection)`
**Severity:** error

---

## Microservice Transport Security

### SA-NEST-07: Microservice Transport Security

NestJS microservices communicate via transports (TCP, Redis, NATS, gRPC, etc.). Without TLS, authentication, and message validation, inter-service communication is vulnerable to eavesdropping, spoofing, and injection.

```typescript
// VULNERABLE: TCP transport without TLS
const app = await NestFactory.createMicroservice(AppModule, {
  transport: Transport.TCP,
  options: {
    host: '0.0.0.0', // Listening on all interfaces
    port: 3001,
    // No TLS — plaintext inter-service communication
  },
});

// VULNERABLE: Redis transport without auth
const app = await NestFactory.createMicroservice(AppModule, {
  transport: Transport.REDIS,
  options: {
    host: 'redis-host',
    port: 6379,
    // No password, no TLS
  },
});

// VULNERABLE: No message validation in handler
@MessagePattern('user.delete')
async deleteUser(data: any) {
  // No validation — trusting inter-service messages blindly
  return this.usersService.delete(data.userId);
}
```

```typescript
// SECURE: gRPC with TLS
const app = await NestFactory.createMicroservice(AppModule, {
  transport: Transport.GRPC,
  options: {
    package: 'users',
    protoPath: join(__dirname, 'users.proto'),
    credentials: grpc.ServerCredentials.createSsl(
      fs.readFileSync('ca.pem'),
      [{ cert_chain: fs.readFileSync('server-cert.pem'),
         private_key: fs.readFileSync('server-key.pem') }],
      true,
    ),
    url: '0.0.0.0:5000',
  },
});

// SECURE: Redis with auth and TLS
const app = await NestFactory.createMicroservice(AppModule, {
  transport: Transport.REDIS,
  options: {
    host: process.env.REDIS_HOST,
    port: 6380,
    password: process.env.REDIS_PASSWORD,
    tls: { rejectUnauthorized: true },
  },
});

// SECURE: Validate microservice messages
@MessagePattern('user.delete')
async deleteUser(@Payload(new ValidationPipe()) data: DeleteUserDto) {
  return this.usersService.delete(data.userId);
}
```

**Detection regex:** `Transport\.(TCP|REDIS|NATS)\s*,\s*\n\s*options\s*:\s*\{(?![\s\S]*?tls|[\s\S]*?password)`
**Severity:** warning

---

## GraphQL Resolver Auth

### SA-NEST-08: GraphQL Resolver Authorization

NestJS GraphQL resolvers are not protected by HTTP guards unless explicitly decorated. Without `@UseGuards()` on resolvers or a global guard, any authenticated or unauthenticated user can query or mutate data.

```typescript
// VULNERABLE: No guards on resolver
@Resolver(() => User)
export class UsersResolver {
  @Query(() => [User])
  users() {
    // Any client can query all users
    return this.usersService.findAll();
  }

  @Mutation(() => Boolean)
  deleteUser(@Args('id') id: string) {
    // Any client can delete any user
    return this.usersService.delete(id);
  }
}

// VULNERABLE: Guard on query but not mutation
@Resolver(() => User)
export class UsersResolver {
  @UseGuards(GqlAuthGuard)
  @Query(() => [User])
  users() {
    return this.usersService.findAll();
  }

  // No guard!
  @Mutation(() => User)
  updateUser(@Args('input') input: UpdateUserInput) {
    return this.usersService.update(input);
  }
}
```

```typescript
// SECURE: Guards on resolver class and sensitive mutations
@Resolver(() => User)
@UseGuards(GqlAuthGuard) // All queries/mutations require auth
export class UsersResolver {
  @Query(() => [User])
  users(@CurrentUser() user: User) {
    return this.usersService.findAll();
  }

  @Roles('admin')
  @UseGuards(GqlRolesGuard)
  @Mutation(() => Boolean)
  deleteUser(@Args('id') id: string) {
    return this.usersService.delete(id);
  }

  @Mutation(() => User)
  updateUser(
    @CurrentUser() user: User,
    @Args('input', new ValidationPipe()) input: UpdateUserInput,
  ) {
    // Verify ownership
    if (input.id !== user.id) throw new ForbiddenException();
    return this.usersService.update(input);
  }
}
```

**Detection regex:** `@(Mutation|Query)\s*\([^)]*\)\s*\n\s*(?:async\s+)?\w+\s*\((?![\s\S]*?@UseGuards|[\s\S]*?@Roles)`
**Severity:** error

---

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-NEST-01 Guard ordering | Critical | Immediate | Low |
| SA-NEST-02 DTO validation bypass | Critical | Immediate | Medium |
| SA-NEST-03 Interceptor data leakage | High | 1 week | Medium |
| SA-NEST-04 Pipe validation bypass | Medium | 1 week | Low |
| SA-NEST-05 @Public decorator misuse | Critical | Immediate | Low |
| SA-NEST-06 WebSocket gateway auth | High | 1 week | Medium |
| SA-NEST-07 Microservice transport | Medium | 1 month | High |
| SA-NEST-08 GraphQL resolver auth | High | 1 week | Medium |

## Related References

- `owasp-top10.md` -- OWASP Top 10 mapping
- `api-security.md` -- API-level security patterns
- NestJS Security documentation: https://docs.nestjs.com/security/authentication

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 3 framework expansion |
