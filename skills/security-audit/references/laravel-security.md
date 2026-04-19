# Laravel Security Patterns

Security patterns specific to Laravel — Gates/Policies, mass assignment, CSRF, Crypt facade, Query Builder. Cross-framework patterns live in `framework-security.md`.

## Gates and Policies

```php
<?php
declare(strict_types=1);

use Illuminate\Support\Facades\Gate as GateFacade;

// Define gates in AuthServiceProvider
final class AuthServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        // Simple gate: closure-based
        GateFacade::define('manage-settings', function (User $user): bool {
            return $user->is_admin;
        });

        // Gate with resource: checks ownership
        GateFacade::define('update-post', function (User $user, Post $post): bool {
            return $user->id === $post->user_id;
        });
    }
}

// Policy class for fine-grained authorization
final class PostPolicy
{
    /**
     * Determine if the user can view the post.
     */
    public function view(User $user, Post $post): bool
    {
        return $post->published || $user->id === $post->user_id;
    }

    /**
     * Determine if the user can update the post.
     */
    public function update(User $user, Post $post): bool
    {
        return $user->id === $post->user_id;
    }

    /**
     * Determine if the user can delete the post.
     */
    public function delete(User $user, Post $post): bool
    {
        return $user->id === $post->user_id
            && $user->hasRole('editor');
    }
}

// Usage in controller:
final class PostController extends Controller
{
    public function update(Request $request, Post $post): JsonResponse
    {
        // Throws AuthorizationException if denied
        $this->authorize('update', $post);

        $validated = $request->validate([
            'title' => 'required|string|max:255',
            'body' => 'required|string',
        ]);

        $post->update($validated);

        return response()->json($post);
    }
}

// Usage in Blade template:
// @can('update', $post)
//     <a href="{{ route('posts.edit', $post) }}">Edit</a>
// @endcan
```

## Mass Assignment Protection

```php
<?php
declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;

// VULNERABLE: No mass assignment protection
class PostUnsafe extends Model
{
    protected $guarded = [];  // NEVER do this in production
}

// VULNERABLE: Using $request->all() with guarded = []
// Post::create($request->all());  // All fields from request are saved

// SECURE: Explicit fillable (allowlist -- recommended)
class Post extends Model
{
    /**
     * Only these fields can be mass-assigned.
     * @var list<string>
     */
    protected $fillable = [
        'title',
        'body',
        'category_id',
    ];

    // These fields are automatically protected:
    // id, user_id, is_published, is_featured, created_at, updated_at
}

// SECURE: Using validated data only (defense in depth)
final class PostController extends Controller
{
    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'title' => 'required|string|max:255',
            'body' => 'required|string|max:50000',
            'category_id' => 'required|exists:categories,id',
        ]);

        // Even with $fillable, always use validated data
        $post = $request->user()->posts()->create($validated);

        return response()->json($post, 201);
    }
}

// SECURE: Form Request for complex validation
final class StorePostRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('create', Post::class);
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'title' => ['required', 'string', 'max:255'],
            'body' => ['required', 'string'],
            'category_id' => ['required', 'integer', 'exists:categories,id'],
            // is_published, user_id, etc. are NOT in rules = cannot be submitted
        ];
    }
}
```

## CSRF Middleware

```php
<?php
declare(strict_types=1);

// Laravel includes CSRF middleware by default for web routes.
// The VerifyCsrfToken middleware checks _token on all POST/PUT/PATCH/DELETE requests.

// In Blade templates:
// <form method="POST" action="/posts">
//     @csrf                                    <!-- Adds hidden _token field -->
//     <input type="text" name="title">
//     <button type="submit">Create</button>
// </form>

// For AJAX requests:
// <meta name="csrf-token" content="{{ csrf_token() }}">
// <script>
//   fetch('/api/endpoint', {
//       method: 'POST',
//       headers: {
//           'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content,
//           'Content-Type': 'application/json',
//       },
//       body: JSON.stringify(data)
//   });
// </script>

// Exclude routes from CSRF (use sparingly, e.g., for webhooks):
// In app/Http/Middleware/VerifyCsrfToken.php:
final class VerifyCsrfToken extends Middleware
{
    /**
     * URIs that should be excluded from CSRF verification.
     * WARNING: Only exclude routes that have alternative authentication
     * (e.g., webhook signature verification, API tokens).
     *
     * @var list<string>
     */
    protected $except = [
        'webhooks/stripe',    // Uses Stripe signature verification
        'webhooks/github',    // Uses GitHub HMAC verification
    ];
}
```

## Encryption (Crypt Facade)

```php
<?php
declare(strict_types=1);

use Illuminate\Support\Facades\Crypt;
use Illuminate\Contracts\Encryption\DecryptException;

// Laravel's Crypt facade uses AES-256-CBC with HMAC (encrypt-then-MAC)
// Key is derived from APP_KEY in .env

final class SecureStorageService
{
    /**
     * Encrypt sensitive data for storage.
     */
    public function store(string $sensitiveData): string
    {
        // Crypt::encrypt serializes and encrypts (handles objects/arrays too)
        return Crypt::encryptString($sensitiveData);

        // For arrays/objects:
        // return Crypt::encrypt(['key' => 'value']);
    }

    /**
     * Decrypt stored data.
     */
    public function retrieve(string $encryptedData): string
    {
        try {
            return Crypt::decryptString($encryptedData);
        } catch (DecryptException $e) {
            // Tampered data, wrong key, or corrupted ciphertext
            throw new \RuntimeException('Data integrity check failed', 0, $e);
        }
    }
}

// IMPORTANT: Protect APP_KEY
// - Never commit APP_KEY to version control
// - Rotate with: php artisan key:generate
// - After rotation, re-encrypt all data encrypted with old key
// - Store in environment variable, never in config files
```

## Query Builder Parameterization

```php
<?php
declare(strict_types=1);

use Illuminate\Support\Facades\DB;

// VULNERABLE: Raw string concatenation
$users = DB::select("SELECT * FROM users WHERE name = '" . $name . "'");

// VULNERABLE: Raw expression without binding
$users = DB::table('users')
    ->whereRaw("name = '$name'")  // SQL injection
    ->get();

// SECURE: Query builder with automatic parameterization
$users = DB::table('users')
    ->where('name', '=', $name)     // Parameterized automatically
    ->where('active', true)
    ->get();

// SECURE: Raw queries with parameter binding
$users = DB::select(
    'SELECT * FROM users WHERE name = ? AND role = ?',
    [$name, $role]
);

// SECURE: Named bindings
$users = DB::select(
    'SELECT * FROM users WHERE name = :name',
    ['name' => $name]
);

// SECURE: whereRaw with bindings (when raw SQL is needed)
$users = DB::table('users')
    ->whereRaw('LOWER(email) = ?', [strtolower($email)])
    ->get();

// SECURE: Eloquent ORM (always parameterized)
$users = User::where('name', $name)
    ->where('active', true)
    ->get();

// SECURE: Subqueries
$latestPosts = DB::table('posts')
    ->select('user_id', DB::raw('MAX(created_at) as last_post'))
    ->groupBy('user_id');

$users = DB::table('users')
    ->joinSub($latestPosts, 'latest_posts', function ($join) {
        $join->on('users.id', '=', 'latest_posts.user_id');
    })
    ->get();
```

## Detection Patterns for Laravel

```php
// Grep patterns for Laravel security issues:
$laravelPatterns = [
    'protected \$guarded = \[\]',           // Empty guarded array
    '->fill\(\$request->all\(\)\)',         // Mass assignment with all()
    '::create\(\$request->all\(\)\)',       // Create with all request data
    'DB::raw\(\$',                          // Raw SQL with variable
    'whereRaw\(.*\$',                       // whereRaw with variable interpolation
    'DB::select\(.*\.\s*\$',               // Concatenated SQL
    'Crypt::decrypt.*catch.*\{\}',         // Swallowed decryption errors
    'except.*=.*\[.*\*',                   // Wildcard CSRF exclusion
    'auth\(\)->user\(\).*without.*check',  // Missing null check on user
    'APP_KEY.*base64:.*config',            // Hardcoded APP_KEY
];
```

---

