# Cryptography Guide for PHP

## PHP Sodium Functions Reference

PHP 7.2+ includes libsodium as a core extension. Sodium provides high-level, misuse-resistant cryptographic primitives. It is the recommended cryptography library for PHP applications.

### sodium_crypto_secretbox -- Symmetric Encryption

XSalsa20-Poly1305 authenticated encryption. Use when both parties share a secret key.

```php
<?php
declare(strict_types=1);

final class SymmetricEncryption
{
    /**
     * Encrypt data with a shared secret key.
     *
     * Algorithm: XSalsa20-Poly1305
     * Key size: 32 bytes (SODIUM_CRYPTO_SECRETBOX_KEYBYTES)
     * Nonce size: 24 bytes (SODIUM_CRYPTO_SECRETBOX_NONCEBYTES)
     * Auth tag: 16 bytes (SODIUM_CRYPTO_SECRETBOX_MACBYTES)
     */
    public function encrypt(string $plaintext, string $key): string
    {
        // Generate a unique random nonce for every encryption
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);

        // Clear plaintext from memory
        sodium_memzero($plaintext);

        // Prepend nonce to ciphertext for storage
        return $nonce . $ciphertext;
    }

    public function decrypt(string $message, string $key): string
    {
        if (strlen($message) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES) {
            throw new \InvalidArgumentException('Message too short');
        }

        $nonce = substr($message, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = substr($message, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);

        if ($plaintext === false) {
            throw new \RuntimeException('Decryption failed: authentication tag mismatch');
        }

        return $plaintext;
    }

    /**
     * Generate a new random encryption key.
     */
    public static function generateKey(): string
    {
        return sodium_crypto_secretbox_keygen();
    }
}
```

### sodium_crypto_box -- Asymmetric / Public-Key Encryption

X25519-XSalsa20-Poly1305. Use when sender and recipient have separate key pairs.

```php
<?php
declare(strict_types=1);

final class AsymmetricEncryption
{
    /**
     * Generate a key pair for public-key encryption.
     *
     * @return array{publicKey: string, secretKey: string}
     */
    public static function generateKeyPair(): array
    {
        $keypair = sodium_crypto_box_keypair();

        return [
            'publicKey' => sodium_crypto_box_publickey($keypair),
            'secretKey' => sodium_crypto_box_secretkey($keypair),
        ];
    }

    /**
     * Encrypt a message for a specific recipient.
     *
     * @param string $plaintext Message to encrypt
     * @param string $recipientPublicKey Recipient's public key
     * @param string $senderSecretKey Sender's secret key
     */
    public function encrypt(
        string $plaintext,
        string $recipientPublicKey,
        string $senderSecretKey,
    ): string {
        $nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);

        $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $senderSecretKey,
            $recipientPublicKey,
        );

        $ciphertext = sodium_crypto_box($plaintext, $nonce, $keypair);

        sodium_memzero($plaintext);
        sodium_memzero($keypair);

        return $nonce . $ciphertext;
    }

    /**
     * Decrypt a message from a specific sender.
     *
     * @param string $message Nonce + ciphertext
     * @param string $senderPublicKey Sender's public key
     * @param string $recipientSecretKey Recipient's secret key
     */
    public function decrypt(
        string $message,
        string $senderPublicKey,
        string $recipientSecretKey,
    ): string {
        $nonce = substr($message, 0, SODIUM_CRYPTO_BOX_NONCEBYTES);
        $ciphertext = substr($message, SODIUM_CRYPTO_BOX_NONCEBYTES);

        $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $recipientSecretKey,
            $senderPublicKey,
        );

        $plaintext = sodium_crypto_box_open($ciphertext, $nonce, $keypair);

        sodium_memzero($keypair);

        if ($plaintext === false) {
            throw new \RuntimeException('Decryption failed');
        }

        return $plaintext;
    }

    /**
     * Anonymous encryption: sender does not need a key pair.
     * Only the recipient can decrypt (sealed box).
     */
    public function sealedEncrypt(string $plaintext, string $recipientPublicKey): string
    {
        $ciphertext = sodium_crypto_box_seal($plaintext, $recipientPublicKey);
        sodium_memzero($plaintext);
        return $ciphertext;
    }

    public function sealedDecrypt(string $ciphertext, string $keypair): string
    {
        $plaintext = sodium_crypto_box_seal_open($ciphertext, $keypair);

        if ($plaintext === false) {
            throw new \RuntimeException('Sealed box decryption failed');
        }

        return $plaintext;
    }
}
```

### sodium_crypto_sign -- Digital Signatures

Ed25519 signatures. Use to verify message authenticity and integrity without encryption.

```php
<?php
declare(strict_types=1);

final class DigitalSignature
{
    /**
     * Generate a signing key pair.
     *
     * @return array{publicKey: string, secretKey: string}
     */
    public static function generateKeyPair(): array
    {
        $keypair = sodium_crypto_sign_keypair();

        return [
            'publicKey' => sodium_crypto_sign_publickey($keypair),
            'secretKey' => sodium_crypto_sign_secretkey($keypair),
        ];
    }

    /**
     * Sign a message. The message is NOT encrypted -- only signed.
     * Returns the signature prepended to the message.
     */
    public function sign(string $message, string $secretKey): string
    {
        return sodium_crypto_sign($message, $secretKey);
    }

    /**
     * Verify and extract the original message.
     *
     * @throws \RuntimeException If signature verification fails
     */
    public function verify(string $signedMessage, string $publicKey): string
    {
        $message = sodium_crypto_sign_open($signedMessage, $publicKey);

        if ($message === false) {
            throw new \RuntimeException('Signature verification failed');
        }

        return $message;
    }

    /**
     * Create a detached signature (signature separate from message).
     */
    public function signDetached(string $message, string $secretKey): string
    {
        return sodium_crypto_sign_detached($message, $secretKey);
    }

    /**
     * Verify a detached signature.
     */
    public function verifyDetached(string $signature, string $message, string $publicKey): bool
    {
        return sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
    }
}
```

### sodium_crypto_pwhash -- Password Hashing

Argon2id password hashing via Sodium. An alternative to `password_hash()` with more control over parameters.

```php
<?php
declare(strict_types=1);

final class PasswordHasher
{
    /**
     * Hash a password using Argon2id via Sodium.
     * Returns a string safe for storage (includes salt, algorithm, parameters).
     */
    public function hash(string $password): string
    {
        $hash = sodium_crypto_pwhash_str(
            $password,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,    // CPU cost
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,    // Memory cost (256 MB)
        );

        sodium_memzero($password);

        return $hash;
    }

    /**
     * Verify a password against a stored hash.
     */
    public function verify(string $password, string $hash): bool
    {
        $result = sodium_crypto_pwhash_str_verify($hash, $password);

        sodium_memzero($password);

        return $result;
    }

    /**
     * Check if a hash needs rehashing (parameters have been upgraded).
     */
    public function needsRehash(string $hash): bool
    {
        return sodium_crypto_pwhash_str_needs_rehash(
            $hash,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
        );
    }

    /**
     * Derive a cryptographic key from a password.
     * Use this when you need a fixed-length key, not for password storage.
     */
    public function deriveKey(string $password, string $salt): string
    {
        if (strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            throw new \InvalidArgumentException('Salt must be exactly ' . SODIUM_CRYPTO_PWHASH_SALTBYTES . ' bytes');
        }

        $key = sodium_crypto_pwhash(
            SODIUM_CRYPTO_SECRETBOX_KEYBYTES,          // 32 bytes
            $password,
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
        );

        sodium_memzero($password);

        return $key;
    }
}
```

**Comparison: sodium_crypto_pwhash vs password_hash**

| Feature | `password_hash()` | `sodium_crypto_pwhash_str()` |
|---------|-------------------|------------------------------|
| Simplicity | Higher (auto-selects params) | Lower (explicit params) |
| Algorithm control | PASSWORD_ARGON2ID | Argon2id (same underlying) |
| Memory control | Via options array | Explicit constants |
| Key derivation | Not supported | `sodium_crypto_pwhash()` |
| Rehash check | `password_needs_rehash()` | `sodium_crypto_pwhash_str_needs_rehash()` |
| Recommendation | General password hashing | When you also need key derivation |

### sodium_memzero -- Memory Clearing

```php
<?php
declare(strict_types=1);

// VULNERABLE: Sensitive data remains in memory after use
function processSecret(string $apiKey): void
{
    $result = callApi($apiKey);
    // $apiKey still in memory -- can be found in core dumps, swapped memory
}

// SECURE: Clear sensitive data from memory when done
function processSecretSafe(string $apiKey): void
{
    try {
        $result = callApi($apiKey);
    } finally {
        sodium_memzero($apiKey);  // Overwrites memory with zeros
    }
}

// Pattern: Use in destructors for objects holding secrets
final class SecretHolder
{
    private string $secret;

    public function __construct(string $secret)
    {
        $this->secret = $secret;
    }

    public function __destruct()
    {
        sodium_memzero($this->secret);
    }

    public function getSecret(): string
    {
        return $this->secret;
    }
}
```

---

## Common Cryptographic Mistakes

### ECB Mode (Pattern-Preserving)

```php
<?php
declare(strict_types=1);

// VULNERABLE: ECB mode preserves patterns in plaintext
// Identical plaintext blocks produce identical ciphertext blocks
$ciphertext = openssl_encrypt(
    $data,
    'aes-256-ecb',  // NEVER use ECB mode
    $key,
);

// SECURE: Use authenticated encryption modes
$ciphertext = openssl_encrypt(
    $data,
    'aes-256-gcm',  // GCM provides authentication + confidentiality
    $key,
    OPENSSL_RAW_DATA,
    $iv,
    $tag,  // Authentication tag (output parameter)
);

// BEST: Use Sodium instead of OpenSSL
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$ciphertext = sodium_crypto_secretbox($data, $nonce, $key);
```

### Weak Algorithms

```php
<?php
declare(strict_types=1);

// VULNERABLE: Weak/broken algorithms - DO NOT USE
$hash = md5($data);           // Collision attacks since 2004
$hash = sha1($data);          // Collision attacks since 2017
$encrypted = openssl_encrypt($data, 'des-ecb', $key);      // 56-bit key, brute-forceable
$encrypted = openssl_encrypt($data, 'des-ede3-cbc', $key);  // 3DES: slow, 112-bit effective
$encrypted = openssl_encrypt($data, 'rc4', $key);            // RC4: multiple biases known

// SECURE: Use strong algorithms
$hash = hash('sha256', $data);                  // For checksums/integrity (not passwords)
$hash = hash('sha3-256', $data);                // SHA-3 alternative
$hash = password_hash($pw, PASSWORD_ARGON2ID);  // For password hashing
$encrypted = sodium_crypto_secretbox($data, $nonce, $key);  // For encryption
```

### Hardcoded Keys and IVs

```php
<?php
declare(strict_types=1);

// VULNERABLE: Hardcoded encryption key
final class EncryptionServiceUnsafe
{
    // Key visible in source code, version control, decompiled binaries
    private const string KEY = 'my-super-secret-key-12345678901';
    private const string IV = '1234567890123456';  // Static IV is also dangerous

    public function encrypt(string $data): string
    {
        return openssl_encrypt($data, 'aes-256-cbc', self::KEY, 0, self::IV);
    }
}

// SECURE: Key from environment/secrets manager, random IV per operation
final class EncryptionServiceSafe
{
    private readonly string $key;

    public function __construct()
    {
        $keyHex = getenv('ENCRYPTION_KEY');
        if ($keyHex === false || $keyHex === '') {
            throw new \RuntimeException('ENCRYPTION_KEY environment variable not set');
        }

        $this->key = hex2bin($keyHex);
        if ($this->key === false || strlen($this->key) !== 32) {
            throw new \RuntimeException('ENCRYPTION_KEY must be 64 hex characters (32 bytes)');
        }
    }

    public function encrypt(string $data): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($data, $nonce, $this->key);
        sodium_memzero($data);
        return base64_encode($nonce . $ciphertext);
    }
}
```

### Predictable Random Numbers

```php
<?php
declare(strict_types=1);

// VULNERABLE: Predictable random number generators - DO NOT USE for security
$token = rand(0, 999999);                    // Linear congruential generator
$token = mt_rand(0, 999999);                 // Mersenne Twister (predictable)
$token = md5(uniqid());                      // uniqid() based on time (predictable)
$token = md5(microtime());                   // Time-based (predictable)
$token = substr(str_shuffle('abc...'), 0, 32); // str_shuffle uses mt_rand internally

// SECURE: Cryptographically secure random generators
$token = random_bytes(32);                   // 32 bytes of CSPRNG output
$token = bin2hex(random_bytes(32));           // 64-char hex string
$token = base64_encode(random_bytes(32));     // Base64 encoded
$integer = random_int(0, 999999);             // Cryptographically secure integer
```

### Missing Authenticated Encryption

```php
<?php
declare(strict_types=1);

// VULNERABLE: AES-CBC without authentication (susceptible to padding oracle attacks)
function encryptUnsafe(string $data, string $key): string
{
    $iv = random_bytes(16);
    $ciphertext = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    // No authentication tag -- attacker can modify ciphertext without detection
    return $iv . $ciphertext;
}

// VULNERABLE: Encrypt-then-MAC with wrong order
function encryptBadMac(string $data, string $key): string
{
    $iv = random_bytes(16);
    // MAC-then-encrypt (wrong order) -- MAC is encrypted, cannot verify before decrypting
    $mac = hash_hmac('sha256', $data, $key, true);
    $ciphertext = openssl_encrypt($mac . $data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return $iv . $ciphertext;
}

// SECURE: Use authenticated encryption (AEAD)
function encryptAead(string $data, string $key): string
{
    // Option 1: Sodium (recommended)
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $ciphertext = sodium_crypto_secretbox($data, $nonce, $key);
    return $nonce . $ciphertext;  // Authentication built in

    // Option 2: AES-256-GCM via OpenSSL
    // $iv = random_bytes(12);  // GCM uses 12-byte IV
    // $ciphertext = openssl_encrypt($data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    // return $iv . $tag . $ciphertext;  // Store IV + tag + ciphertext
}
```

### Nonce Reuse

```php
<?php
declare(strict_types=1);

// VULNERABLE: Reusing the same nonce with the same key
// With XSalsa20 (stream cipher), nonce reuse reveals plaintext XOR:
// C1 = P1 XOR keystream(nonce, key)
// C2 = P2 XOR keystream(nonce, key)
// C1 XOR C2 = P1 XOR P2 (plaintext relationship exposed)

final class BrokenEncryption
{
    private string $nonce;

    public function __construct(private readonly string $key)
    {
        // Nonce generated once and reused for all encryptions
        $this->nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    }

    public function encrypt(string $data): string
    {
        // VULNERABLE: Same nonce used for every call
        return sodium_crypto_secretbox($data, $this->nonce, $this->key);
    }
}

// SECURE: Fresh random nonce for every encryption
final class CorrectEncryption
{
    public function __construct(private readonly string $key) {}

    public function encrypt(string $data): string
    {
        // New random nonce every time -- collision probability negligible for 24-byte nonces
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($data, $nonce, $this->key);
        return $nonce . $ciphertext;
    }
}

// Alternative: Counter-based nonce (when random nonce is not suitable)
// Use only if you can guarantee atomic incrementing (e.g., database sequence)
```

---

## HKDF for Key Derivation

`hash_hkdf()` (PHP 7.1.2+) implements HKDF (RFC 5869) for deriving multiple keys from a single master key.

```php
<?php
declare(strict_types=1);

final class KeyDerivation
{
    /**
     * Derive purpose-specific keys from a master key using HKDF.
     *
     * HKDF = Extract-then-Expand:
     *   1. Extract: Concentrates entropy from input key material
     *   2. Expand: Generates output key material with domain separation
     *
     * @param string $masterKey The input key material (IKM)
     * @param string $purpose Domain separator (e.g., 'encryption', 'signing')
     * @param int $length Desired output key length in bytes
     * @param string $salt Optional salt (recommended: random, at least hash-length)
     */
    public static function derive(
        string $masterKey,
        string $purpose,
        int $length = 32,
        string $salt = '',
    ): string {
        return hash_hkdf(
            'sha256',       // Hash algorithm
            $masterKey,     // Input key material
            $length,        // Output length
            $purpose,       // Info string (domain separator)
            $salt,          // Salt (empty string = zeros)
        );
    }

    /**
     * Derive multiple independent keys from a single master key.
     * Each key is cryptographically independent due to different info strings.
     *
     * @return array{encryption: string, signing: string, tokenGeneration: string}
     */
    public static function deriveKeySet(string $masterKey): array
    {
        $salt = random_bytes(32);  // Same salt for all derivations in this set

        return [
            'encryption' => self::derive($masterKey, 'app:encryption:v1', 32, $salt),
            'signing' => self::derive($masterKey, 'app:signing:v1', 32, $salt),
            'tokenGeneration' => self::derive($masterKey, 'app:tokens:v1', 32, $salt),
        ];
    }
}

// Usage: Deriving context-specific keys
// $masterKey = getenv('APP_MASTER_KEY');
// $encKey = KeyDerivation::derive($masterKey, 'database:encryption:v1');
// $signKey = KeyDerivation::derive($masterKey, 'api:request-signing:v1');
```

**When to use HKDF vs raw SHA-256:**

| Scenario | Use HKDF | Use SHA-256 |
|----------|----------|-------------|
| Deriving multiple keys from one master | Yes | No (related outputs) |
| Key material from a key exchange | Yes | No (may lack entropy spread) |
| Simple key stretching from high-entropy input | Either | Either |
| Password-based key derivation | No (use Argon2id) | No (use Argon2id) |

---

## OpenSSL vs Sodium Comparison

| Feature | OpenSSL (`openssl_*`) | Sodium (`sodium_*`) |
|---------|----------------------|---------------------|
| API complexity | Many algorithm choices, easy to misconfigure | Few functions, hard to misuse |
| Authenticated encryption | Must choose GCM/CCM and manage tags | Built in (secretbox, box) |
| Key management | Manual | Keygen functions provided |
| Memory safety | No zeroing | `sodium_memzero()` available |
| Algorithm selection | Developer chooses (risk of weak choice) | Curated safe defaults |
| Padding | Must handle (CBC padding oracle risk) | No padding needed (stream cipher) |
| IV/Nonce handling | Manual (risk of reuse) | Clear constants for nonce sizes |
| Availability | PHP core since 5.3 | PHP core since 7.2 |
| Performance | Hardware AES-NI when available | Optimized C implementations |
| Recommendation | Legacy systems only | Preferred for new development |

**When to use OpenSSL:**

- Interoperating with systems that require specific algorithms (AES-256-GCM, RSA)
- Working with X.509 certificates and TLS
- Legacy systems that cannot be migrated

**When to use Sodium:**

- All new development (default choice)
- When simplicity and safety are priorities
- When interoperating with other libsodium implementations (NaCl, TweetNaCl)

```php
<?php
declare(strict_types=1);

// OpenSSL AES-256-GCM (when you must use OpenSSL)
final class OpenSslEncryption
{
    private const string CIPHER = 'aes-256-gcm';
    private const int IV_LENGTH = 12;   // GCM standard
    private const int TAG_LENGTH = 16;  // 128-bit auth tag

    public function encrypt(string $data, string $key): string
    {
        $iv = random_bytes(self::IV_LENGTH);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $data,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',               // AAD (additional authenticated data)
            self::TAG_LENGTH,
        );

        if ($ciphertext === false) {
            throw new \RuntimeException('Encryption failed: ' . openssl_error_string());
        }

        // Store: IV || Tag || Ciphertext
        return $iv . $tag . $ciphertext;
    }

    public function decrypt(string $message, string $key): string
    {
        $iv = substr($message, 0, self::IV_LENGTH);
        $tag = substr($message, self::IV_LENGTH, self::TAG_LENGTH);
        $ciphertext = substr($message, self::IV_LENGTH + self::TAG_LENGTH);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
        );

        if ($plaintext === false) {
            throw new \RuntimeException('Decryption failed: authentication or data error');
        }

        return $plaintext;
    }
}
```

---

## Key Management Best Practices

### Key Storage Hierarchy

```
Environment variable or secrets manager (HSM/KMS)
    |
    v
Master key (loaded at application boot, never logged)
    |
    v
HKDF derivation with domain separation
    |
    +--> Database encryption key (purpose: "db:encryption:v1")
    +--> API signing key (purpose: "api:signing:v1")
    +--> Token generation key (purpose: "auth:tokens:v1")
```

### Key Rotation Pattern

```php
<?php
declare(strict_types=1);

final class KeyRotationService
{
    /**
     * Rotate encryption keys. Old data remains readable during transition.
     *
     * Strategy: Decrypt with any known key, encrypt with current key.
     */
    public function __construct(
        private readonly string $currentKey,
        /** @var list<string> Previous keys for decryption only */
        private readonly array $previousKeys = [],
    ) {}

    public function encrypt(string $plaintext): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $this->currentKey);
        sodium_memzero($plaintext);

        // Version prefix allows identifying which key was used
        return 'v2:' . base64_encode($nonce . $ciphertext);
    }

    public function decrypt(string $encrypted): string
    {
        // Try current key first
        $allKeys = array_merge([$this->currentKey], $this->previousKeys);

        // Strip version prefix if present
        $data = $encrypted;
        if (preg_match('/^v\d+:/', $data)) {
            $data = substr($data, strpos($data, ':') + 1);
        }

        $decoded = base64_decode($data, true);
        if ($decoded === false) {
            throw new \InvalidArgumentException('Invalid encoding');
        }

        $nonce = substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        foreach ($allKeys as $key) {
            $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
            if ($plaintext !== false) {
                return $plaintext;
            }
        }

        throw new \RuntimeException('Decryption failed with all available keys');
    }

    /**
     * Re-encrypt data with the current key (for batch migration).
     */
    public function reencrypt(string $encrypted): string
    {
        $plaintext = $this->decrypt($encrypted);
        return $this->encrypt($plaintext);
    }
}
```

### Key Storage Recommendations

| Method | Security Level | Use Case |
|--------|---------------|----------|
| Environment variable | Medium | Single-server, containerized apps |
| AWS KMS / GCP KMS / Azure Key Vault | High | Cloud-hosted applications |
| HashiCorp Vault | High | Multi-cloud, on-premise |
| Hardware Security Module (HSM) | Highest | Financial, healthcare, government |
| Config file on disk | Low | Development only, never production |
| Hardcoded in source | None | Never acceptable |

### Key Lifecycle Checklist

- [ ] Keys generated using CSPRNG (`random_bytes()` or `sodium_crypto_*_keygen()`)
- [ ] Keys stored in environment variables or secrets manager, never in source code
- [ ] Keys rotated on a defined schedule (e.g., annually, or on personnel changes)
- [ ] Old keys retained for decryption of existing data during rotation
- [ ] Key material cleared from memory after use (`sodium_memzero()`)
- [ ] Key access logged and auditable
- [ ] Separate keys per environment (dev, staging, production)
- [ ] Separate keys per purpose (encryption, signing, tokens) via HKDF

---

## Envelope Encryption Pattern

Envelope encryption uses two layers of keys to combine the performance of symmetric encryption with the management benefits of asymmetric encryption or KMS.

```
KMS / Master Key (stored securely, never leaves HSM/KMS)
    |
    |-- Encrypts --> Data Encryption Key (DEK)
                        |
                        |-- Encrypts --> Actual data
```

```php
<?php
declare(strict_types=1);

/**
 * Envelope encryption: encrypt data with a random DEK,
 * then encrypt the DEK with a master key (or KMS).
 */
final class EnvelopeEncryption
{
    public function __construct(
        private readonly string $masterKey,  // In production, replace with KMS API call
    ) {}

    /**
     * Encrypt data using envelope encryption.
     *
     * @return array{encryptedDek: string, encryptedData: string}
     */
    public function encrypt(string $plaintext): array
    {
        // Step 1: Generate a random Data Encryption Key (DEK)
        $dek = sodium_crypto_secretbox_keygen();

        // Step 2: Encrypt the data with the DEK
        $dataNonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $encryptedData = $dataNonce . sodium_crypto_secretbox($plaintext, $dataNonce, $dek);

        // Step 3: Encrypt the DEK with the master key (or via KMS API)
        $dekNonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $encryptedDek = $dekNonce . sodium_crypto_secretbox($dek, $dekNonce, $this->masterKey);

        // Step 4: Clear sensitive material from memory
        sodium_memzero($dek);
        sodium_memzero($plaintext);

        return [
            'encryptedDek' => base64_encode($encryptedDek),
            'encryptedData' => base64_encode($encryptedData),
        ];
    }

    /**
     * Decrypt data using envelope encryption.
     */
    public function decrypt(string $encryptedDekB64, string $encryptedDataB64): string
    {
        // Step 1: Decrypt the DEK with the master key
        $encryptedDek = base64_decode($encryptedDekB64, true);
        $dekNonce = substr($encryptedDek, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $dekCiphertext = substr($encryptedDek, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $dek = sodium_crypto_secretbox_open($dekCiphertext, $dekNonce, $this->masterKey);
        if ($dek === false) {
            throw new \RuntimeException('Failed to decrypt DEK');
        }

        // Step 2: Decrypt the data with the DEK
        $encryptedData = base64_decode($encryptedDataB64, true);
        $dataNonce = substr($encryptedData, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $dataCiphertext = substr($encryptedData, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $plaintext = sodium_crypto_secretbox_open($dataCiphertext, $dataNonce, $dek);

        sodium_memzero($dek);

        if ($plaintext === false) {
            throw new \RuntimeException('Failed to decrypt data');
        }

        return $plaintext;
    }
}
```

**Benefits of envelope encryption:**

- **Key rotation** only requires re-encrypting the DEK, not all data
- **Performance**: data encrypted with fast symmetric cipher, only small DEK needs KMS call
- **Access control**: KMS can enforce policies on who can decrypt the DEK
- **Audit trail**: KMS logs every DEK decrypt operation

### AWS KMS Envelope Encryption Example

```php
<?php
declare(strict_types=1);

use Aws\Kms\KmsClient;

/**
 * Production envelope encryption using AWS KMS.
 * The master key never leaves AWS KMS -- only the DEK is handled locally.
 */
final class AwsEnvelopeEncryption
{
    public function __construct(
        private readonly KmsClient $kms,
        private readonly string $cmkId,  // Customer Master Key ARN
    ) {}

    public function encrypt(string $plaintext): array
    {
        // Step 1: Ask KMS to generate a DEK (returns plaintext + encrypted copies)
        $result = $this->kms->generateDataKey([
            'KeyId' => $this->cmkId,
            'KeySpec' => 'AES_256',
        ]);

        $dek = $result['Plaintext'];                    // Plaintext DEK (use and discard)
        $encryptedDek = $result['CiphertextBlob'];      // Encrypted DEK (store)

        // Step 2: Encrypt data with the plaintext DEK
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $encryptedData = $nonce . sodium_crypto_secretbox($plaintext, $nonce, $dek);

        // Step 3: Clear plaintext DEK from memory
        sodium_memzero($dek);
        sodium_memzero($plaintext);

        return [
            'encryptedDek' => base64_encode($encryptedDek),
            'encryptedData' => base64_encode($encryptedData),
        ];
    }

    public function decrypt(string $encryptedDekB64, string $encryptedDataB64): string
    {
        // Step 1: Ask KMS to decrypt the DEK
        $result = $this->kms->decrypt([
            'CiphertextBlob' => base64_decode($encryptedDekB64, true),
        ]);
        $dek = $result['Plaintext'];

        // Step 2: Decrypt data with the plaintext DEK
        $encryptedData = base64_decode($encryptedDataB64, true);
        $nonce = substr($encryptedData, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = substr($encryptedData, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $dek);
        sodium_memzero($dek);

        if ($plaintext === false) {
            throw new \RuntimeException('Data decryption failed');
        }

        return $plaintext;
    }
}
```

---

## Detection Patterns

### Static Analysis Patterns for Cryptographic Weaknesses

```php
// Grep patterns to find cryptographic vulnerabilities:
$cryptoPatterns = [
    // Weak algorithms
    'md5\(',                             // MD5 (broken for integrity)
    'sha1\(',                            // SHA1 (collision attacks)
    'crc32\(',                           // CRC32 (not cryptographic)
    "'des-",                             // DES encryption
    "'rc4'",                             // RC4 stream cipher
    "'des-ede3",                         // 3DES

    // ECB mode
    "'aes-.*-ecb'",                      // Any AES in ECB mode

    // Predictable randomness
    '\brand\(',                          // rand() for security
    '\bmt_rand\(',                       // mt_rand() for security
    'uniqid\(',                          // uniqid() as entropy source
    'microtime\(',                       // Time-based seed

    // Hardcoded secrets
    "const.*KEY.*=.*['\"]",              // Hardcoded key constants
    "private.*\\\$key.*=.*['\"]",        // Hardcoded key properties
    "define\(.*KEY.*,.*['\"]",           // Hardcoded key defines

    // Missing authentication
    "'aes-.*-cbc'",                      // CBC without HMAC (check context)
    'openssl_encrypt.*cbc',              // CBC mode (verify HMAC exists)

    // Insecure OpenSSL usage
    'OPENSSL_ZERO_PADDING',             // May indicate custom padding (risk)
    'openssl_.*false.*false',           // Disabled error checking
];
```

### Audit Checklist

| Category | Check | Severity |
|----------|-------|----------|
| Algorithm | No MD5/SHA1 for integrity or passwords | Critical |
| Algorithm | No DES/3DES/RC4 | Critical |
| Mode | No ECB mode | Critical |
| Authentication | All encryption uses AEAD (GCM/Poly1305) | High |
| Randomness | All security tokens use `random_bytes()`/`random_int()` | Critical |
| Keys | No hardcoded keys or IVs | Critical |
| Keys | Key derivation uses HKDF with domain separation | High |
| Keys | Key rotation procedure documented and tested | Medium |
| Memory | Sensitive data cleared with `sodium_memzero()` | Medium |
| Nonces | Fresh random nonce per encryption operation | Critical |
| Passwords | Uses Argon2id or bcrypt, not plain hashing | Critical |
| Storage | Encryption keys in env vars or secrets manager | High |
