# Android SDK Security Patterns

Security patterns, common misconfigurations, and detection regexes for Android applications. Covers manifest vulnerabilities, component exposure, insecure storage, WebView risks, network configuration, and cryptographic weaknesses.

## Component Exposure

### Exported Activities Without Intent Filters

Activities declared with `android:exported="true"` are accessible to any application on the device. Without proper intent-filter restrictions or permission requirements, malicious apps can launch these activities directly, potentially bypassing authentication flows or accessing sensitive screens.

```xml
<!-- VULNERABLE: Activity exported without restrictions -->
<activity
    android:name=".AdminActivity"
    android:exported="true">
</activity>

<!-- SECURE: Activity protected with custom permission -->
<activity
    android:name=".AdminActivity"
    android:exported="true"
    android:permission="com.example.ADMIN_PERMISSION">
    <intent-filter>
        <action android:name="com.example.ACTION_ADMIN" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>

<!-- SECURE: Activity not exported (default when no intent-filter) -->
<activity
    android:name=".AdminActivity"
    android:exported="false">
</activity>
```

**Detection guidance:** a plain `android:exported="true"` regex flags both the vulnerable AND the secure example above (the secure one is exported but protected by `android:permission`). Narrow it to "exported without `android:permission` or `intent-filter`", which requires a structural check. XML-aware tooling like `xmlstarlet sel` is the right answer:

```bash
xmlstarlet sel -t -m '//activity[@android:exported="true"][not(@android:permission)][not(intent-filter)]' \
  -v '@android:name' -n AndroidManifest.xml 2>/dev/null
```
**Severity:** error (for exported-without-protection); info (for bare regex matches — review required)

### Implicit Intent Data Leakage

Using implicit intents to pass sensitive data allows any app with a matching intent filter to intercept the information. Always use explicit intents when transmitting sensitive data.

```kotlin
// VULNERABLE: Implicit intent leaking sensitive data
val intent = Intent("com.example.SHARE_DATA")
intent.putExtra("auth_token", token)
startActivity(intent)

// SECURE: Explicit intent targeting specific component
val intent = Intent(this, DataReceiverActivity::class.java)
intent.putExtra("auth_token", token)
startActivity(intent)
```

**Detection regex (Java + Kotlin — `new` is optional):** `(new\s+)?Intent\s*\(\s*"[^"]+"\s*\)[\s\S]{0,120}putExtra\s*\(\s*"(auth|token|session|password|secret|key|credential)` — run with `grep -rP` across `.java` and `.kt` files.
**Severity:** warning

### Exported Broadcast Receivers Without Permissions

Broadcast receivers exported without permission restrictions allow any app to send them broadcasts, triggering unintended actions or injecting malicious data.

```kotlin
// VULNERABLE: Dynamically registering receiver without permission
registerReceiver(receiver, IntentFilter("com.example.PAYMENT_COMPLETE"))

// SECURE: Register with permission requirement
registerReceiver(receiver, IntentFilter("com.example.PAYMENT_COMPLETE"),
    "com.example.PAYMENT_PERMISSION", null)
```

**Detection regex (two-argument form only — permission-protected calls take 3+ args):** `registerReceiver\s*\(\s*[^,]+,\s*[^,)]+\)` — run with `grep -rP` across `.java` and `.kt`. The permission-protected overload has a third `String broadcastPermission` argument, so this pattern skips it.
**Severity:** warning

## ContentProvider Vulnerabilities

### SQL Injection via ContentProvider query()

ContentProviders that build SQL queries by concatenating user-supplied `selection` arguments are vulnerable to SQL injection. Always use parameterized `selectionArgs` to safely pass values.

```java
// VULNERABLE: SQL injection in ContentProvider query
@Override
public Cursor query(Uri uri, String[] projection, String selection,
                    String[] selectionArgs, String sortOrder) {
    String userId = uri.getLastPathSegment();
    // Direct concatenation allows SQL injection
    String rawQuery = "SELECT * FROM users WHERE id = " + userId;
    return db.rawQuery(rawQuery, null);
}

// SECURE: Parameterized query with selectionArgs
@Override
public Cursor query(Uri uri, String[] projection, String selection,
                    String[] selectionArgs, String sortOrder) {
    String userId = uri.getLastPathSegment();
    return db.query("users", projection, "id = ?",
                    new String[]{userId}, null, null, sortOrder);
}
```

```kotlin
// VULNERABLE: Raw query concatenation in Kotlin ContentProvider
override fun query(
    uri: Uri, projection: Array<String>?, selection: String?,
    selectionArgs: Array<String>?, sortOrder: String?
): Cursor? {
    val id = uri.lastPathSegment
    return db.rawQuery("SELECT * FROM items WHERE id = $id", null)
}

// SECURE: Parameterized query
override fun query(
    uri: Uri, projection: Array<String>?, selection: String?,
    selectionArgs: Array<String>?, sortOrder: String?
): Cursor? {
    val id = uri.lastPathSegment
    return db.query("items", projection, "id = ?",
                    arrayOf(id), null, null, sortOrder)
}
```

**Detection regex:** `rawQuery\s*\(\s*"[^"]*\+\s*\w+|rawQuery\s*\(\s*"[^"]*\$\{?`
**Severity:** error

### Path Traversal in ContentProvider openFile

ContentProviders that expose files via `openFile()` without validating the URI path component are vulnerable to path traversal attacks via `../` sequences.

```java
// VULNERABLE: No path validation in openFile
File file = new File(getContext().getFilesDir(), uri.getLastPathSegment());
return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);

// SECURE: Validate canonical path to prevent traversal
File baseDir = getContext().getFilesDir();
File file = new File(baseDir, uri.getLastPathSegment());
if (!file.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {
    throw new SecurityException("Path traversal detected");
}
```

**Detection regex:** `openFile\s*\(\s*Uri\s+\w+[\s\S]{0,200}getLastPathSegment\s*\(\s*\)(?![\s\S]{0,200}getCanonicalPath)`
**Severity:** error

## WebView Security

### JavaScript Interface on API < 17

Before Android API level 17, `addJavascriptInterface()` allowed JavaScript to invoke any public method on the injected Java object via reflection, leading to arbitrary code execution. On API 17+, only methods annotated with `@JavascriptInterface` are accessible.

```java
// VULNERABLE: addJavascriptInterface without API level check
public class WebViewActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView webView = new WebView(this);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.addJavascriptInterface(new WebAppInterface(), "Android");
        webView.loadUrl("https://example.com");
    }

    // All public methods exposed on API < 17
    public class WebAppInterface {
        public String getToken() {
            return AuthManager.getAuthToken();
        }
    }
}

// SECURE: Check API level and use @JavascriptInterface annotation
public class WebViewActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView webView = new WebView(this);
        webView.getSettings().setJavaScriptEnabled(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            webView.addJavascriptInterface(new SecureInterface(), "Android");
        }
        webView.loadUrl("https://example.com");
    }

    public class SecureInterface {
        @JavascriptInterface
        public String getPublicData() {
            return "safe-public-data";
        }
    }
}
```

```kotlin
// VULNERABLE: JavaScript interface with untrusted content
class WebViewActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)
        webView.settings.javaScriptEnabled = true
        webView.addJavascriptInterface(AppBridge(), "app")
        // Loading untrusted URL with JS interface exposed
        webView.loadUrl(intent.getStringExtra("url") ?: "")
    }
}

// SECURE: Restrict to trusted origins, validate URLs
class WebViewActivity : AppCompatActivity() {
    private val allowedHosts = setOf("app.example.com", "cdn.example.com")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)
        webView.settings.javaScriptEnabled = true

        val url = intent.getStringExtra("url") ?: return
        val host = Uri.parse(url).host
        if (host in allowedHosts) {
            webView.addJavascriptInterface(AppBridge(), "app")
            webView.loadUrl(url)
        }
    }
}
```

**Detection guidance:** `addJavascriptInterface(…)` itself is not a vulnerability on modern `minSdk`. Flag two specific shapes instead: (1) `addJavascriptInterface(` in a project whose `minSdk` is below 17, and (2) an interface class whose public methods are missing the `@JavascriptInterface` annotation:

```bash
# (1) Find addJavascriptInterface usage and require the caller to verify minSdk.
grep -rnE 'addJavascriptInterface\s*\(' --include='*.java' --include='*.kt' . \
  | while read -r line; do echo "review minSdk: $line"; done

# (2) Detect interface classes where any public method lacks the annotation.
# Heuristic: a class passed to addJavascriptInterface whose next 20 lines
# show a public/fun member without a preceding @JavascriptInterface line.
# Best run through an AST-aware tool (ktlint custom rule, PSI in Android Studio).
```
**Severity:** info (regex match only — requires manual minSdk + annotation review)
**Severity:** error

### WebView File Access

Enabling `setAllowFileAccess(true)` allows JavaScript in the WebView to read device files. Combined with untrusted content, this creates a data exfiltration vector.

```kotlin
// VULNERABLE: File access enabled with JavaScript
webView.settings.apply {
    javaScriptEnabled = true
    allowFileAccess = true
    allowUniversalAccessFromFileURLs = true
}

// SECURE: Disable file access
webView.settings.apply {
    javaScriptEnabled = true
    allowFileAccess = false
    allowFileAccessFromFileURLs = false
    allowUniversalAccessFromFileURLs = false
}
```

**Detection regex:** `setAllowFileAccess\s*\(\s*true\s*\)|allowFileAccess\s*=\s*true`
**Severity:** error

## Insecure Data Storage

### SharedPreferences Without Encryption

Storing sensitive data (passwords, tokens, API keys) in standard `SharedPreferences` exposes them to extraction on rooted devices or via backup access. `MODE_WORLD_READABLE` (deprecated) makes data accessible to all apps on the device.

```kotlin
// VULNERABLE: Storing token in plain SharedPreferences
fun saveAuthToken(context: Context, token: String) {
    val prefs = context.getSharedPreferences("auth", Context.MODE_PRIVATE)
    prefs.edit().putString("access_token", token).apply()
}

// VULNERABLE: MODE_WORLD_READABLE (deprecated but still seen)
val prefs = getSharedPreferences("config", Context.MODE_WORLD_READABLE)
prefs.edit().putString("password", userPassword).apply()

// SECURE: Use EncryptedSharedPreferences from AndroidX Security
fun saveAuthToken(context: Context, token: String) {
    val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    val prefs = EncryptedSharedPreferences.create(
        context,
        "secure_auth",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )
    prefs.edit().putString("access_token", token).apply()
}
```

```java
// VULNERABLE: Storing password in SharedPreferences
SharedPreferences prefs = getSharedPreferences("user", MODE_PRIVATE);
prefs.edit().putString("password", password).apply();

// SECURE: Use EncryptedSharedPreferences
MasterKey masterKey = new MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build();

SharedPreferences prefs = EncryptedSharedPreferences.create(
    context, "secure_user", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
);
prefs.edit().putString("password", password).apply();
```

**Detection regex:** `getSharedPreferences\s*\([^)]*\)\s*[\s\S]{0,80}(putString|edit\(\))[\s\S]{0,80}(password|token|secret|key|credential|session)|MODE_WORLD_READABLE`
**Severity:** error

### SQLite Databases Without Encryption

Unencrypted SQLite databases allow extraction on rooted devices. Use SQLCipher or Room with an encrypted `SupportFactory`.

**Detection regex:** `SQLiteOpenHelper|openOrCreateDatabase\s*\(`
**Severity:** warning

## Network Security Configuration

### Cleartext Traffic Allowed

Allowing cleartext (HTTP) traffic exposes data to man-in-the-middle attacks. Android 9+ blocks cleartext by default, but apps can override this via `NetworkSecurityConfig` or manifest attributes.

```xml
<!-- VULNERABLE: Cleartext traffic allowed globally -->
<application
    android:usesCleartextTraffic="true"
    android:networkSecurityConfig="@xml/network_security_config">
</application>

<!-- network_security_config.xml - VULNERABLE -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>

<!-- network_security_config.xml - SECURE -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <!-- Exception only for local development -->
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="false">10.0.2.2</domain>
    </domain-config>
</network-security-config>
```

**Detection regex:** `usesCleartextTraffic\s*=\s*"true"|cleartextTrafficPermitted\s*=\s*"true"`
**Severity:** error

### Missing Certificate Pinning

Without certificate pinning, any trusted-CA-signed certificate is accepted. Use `<pin-set>` in `network_security_config.xml` or OkHttp `CertificatePinner` for production APIs.

**Detection regex:** `(pin-set|CertificatePinner)`
**Severity:** warning

## Manifest Security Flags

### Debug Mode Enabled

A release build with `android:debuggable="true"` allows attackers to attach debuggers, inspect memory, and bypass security controls.

```xml
<!-- VULNERABLE: Debuggable in manifest (should never be in release) -->
<application
    android:debuggable="true"
    android:label="@string/app_name">
</application>

<!-- SECURE: Remove debuggable flag (defaults to false for release builds) -->
<application
    android:label="@string/app_name">
</application>
```

```groovy
// VULNERABLE: Debuggable enabled in release build type
android {
    buildTypes {
        release {
            debuggable true
            minifyEnabled true
        }
    }
}

// SECURE: Debuggable false for release (this is the default)
android {
    buildTypes {
        release {
            debuggable false
            minifyEnabled true
            shrinkResources true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),
                'proguard-rules.pro'
        }
    }
}
```

**Detection regex:** `android:debuggable\s*=\s*"true"|debuggable\s+true`
**Severity:** error

### Backup Enabled Without Restrictions

`android:allowBackup="true"` (default) lets `adb backup` extract app data including tokens and databases. Set `android:allowBackup="false"` or use `fullBackupContent`/`dataExtractionRules` to exclude sensitive files.

**Detection regex:** `android:allowBackup\s*=\s*"true"`
**Severity:** warning

## Cryptographic Weaknesses

### Insecure Random Number Generation

Using `java.util.Random` for security-sensitive operations (token generation, nonce creation, key derivation) produces predictable output. The seed can be guessed, and the sequence is deterministic.

```java
// VULNERABLE: java.util.Random for token generation
import java.util.Random;

public class TokenGenerator {
    public String generateToken() {
        Random random = new Random();
        byte[] token = new byte[32];
        random.nextBytes(token);
        return Base64.encodeToString(token, Base64.NO_WRAP);
    }
}

// SECURE: SecureRandom for cryptographic randomness
import java.security.SecureRandom;

public class TokenGenerator {
    public String generateToken() {
        SecureRandom random = new SecureRandom();
        byte[] token = new byte[32];
        random.nextBytes(token);
        return Base64.encodeToString(token, Base64.NO_WRAP);
    }
}
```

```kotlin
// VULNERABLE: kotlin.random.Random for session ID
fun generateSessionId(): String {
    val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return (1..32).map { chars[kotlin.random.Random.nextInt(chars.length)] }
        .joinToString("")
}

// SECURE: SecureRandom for session ID
fun generateSessionId(): String {
    val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    val secureRandom = java.security.SecureRandom()
    return (1..32).map { chars[secureRandom.nextInt(chars.length)] }
        .joinToString("")
}
```

**Detection regex:** `new\s+Random\s*\(|java\.util\.Random|kotlin\.random\.Random`
**Severity:** error

### Hardcoded Encryption Keys

Hardcoded keys in source code are trivially extractable via decompilation. Keys should be stored in the Android Keystore or derived at runtime from user credentials.

```kotlin
// VULNERABLE: Hardcoded AES key
object CryptoHelper {
    private val SECRET_KEY = "MyS3cr3tK3y12345".toByteArray()

    fun encrypt(data: String): ByteArray {
        val keySpec = SecretKeySpec(SECRET_KEY, "AES")
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec)
        return cipher.doFinal(data.toByteArray())
    }
}

// SECURE: Use Android Keystore
object CryptoHelper {
    private const val KEY_ALIAS = "app_encryption_key"

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        keyStore.getKey(KEY_ALIAS, null)?.let { return it as SecretKey }

        val keyGen = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        keyGen.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        )
        return keyGen.generateKey()
    }

    fun encrypt(data: String): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        return cipher.doFinal(data.toByteArray())
    }
}
```

```java
// VULNERABLE: Hardcoded key bytes
private static final byte[] KEY = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

// SECURE: Derive key from Android Keystore
KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
keyStore.load(null);
SecretKey key = (SecretKey) keyStore.getKey("my_key_alias", null);
```

**Detection regex:** `SecretKeySpec\s*\(\s*"[^"]+"\s*\.toByteArray|private\s+(static\s+)?final\s+byte\[\]\s+\w*(KEY|key|Key|SECRET|secret|Secret)\s*=`
**Severity:** error

### Weak Cipher Configuration

DES, RC4, and AES/ECB are weak. Use `AES/GCM/NoPadding` for authenticated encryption.

**Detection regex:** `Cipher\.getInstance\s*\(\s*"(DES|RC4|AES/ECB|Blowfish)`
**Severity:** error

## Root Detection

### Missing or Weak Root Detection

Apps handling sensitive data (banking, healthcare, enterprise) should detect rooted devices and respond appropriately. Weak or missing detection allows operation in compromised environments.

```kotlin
// VULNERABLE: No root detection at all

// BASIC (easily bypassed): Simple file check
fun isRooted(): Boolean {
    val paths = arrayOf("/system/app/Superuser.apk", "/sbin/su", "/system/bin/su")
    return paths.any { File(it).exists() }
}

// SECURE: Multi-layered root detection with SafetyNet/Play Integrity
class RootDetector(private val context: Context) {

    fun checkDeviceIntegrity(callback: (Boolean) -> Unit) {
        // 1. File system checks
        if (checkRootBinaries()) {
            callback(false)
            return
        }

        // 2. Build property checks
        if (checkBuildTags()) {
            callback(false)
            return
        }

        // 3. Google Play Integrity API (server-verified)
        val integrityManager = IntegrityManagerFactory.create(context)
        val request = IntegrityTokenRequest.builder()
            .setNonce(generateNonce())
            .build()

        integrityManager.requestIntegrityToken(request)
            .addOnSuccessListener { response ->
                // Verify token on your server, not client-side
                verifyTokenOnServer(response.token(), callback)
            }
            .addOnFailureListener {
                callback(false)
            }
    }

    private fun checkRootBinaries(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su"
        )
        return paths.any { File(it).exists() }
    }

    private fun checkBuildTags(): Boolean {
        val tags = Build.TAGS
        return tags != null && tags.contains("test-keys")
    }
}
```

**Detection regex:** `(SafetyNet|PlayIntegrity|IntegrityManager|isRooted|checkRoot|rootDetect)`
**Severity:** warning

## Logging and Debug Output

### Sensitive Data in Logs

Using `Log.d()`, `Log.v()`, or `Log.i()` with sensitive data in production builds exposes information via `logcat`. Any app with `READ_LOGS` permission (or ADB access) can read these logs.

```kotlin
// VULNERABLE: Logging sensitive data
Log.d("Auth", "User token: $authToken")
Log.i("Payment", "Card number: $cardNumber")
Log.v("API", "Request body: $requestJson")

// SECURE: Use Timber with a release tree that strips verbose/debug
class ReleaseTree : Timber.Tree() {
    override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
        if (priority < Log.WARN) return // Strip DEBUG and VERBOSE in release
        // Send to crash reporting service instead
        CrashReporter.log(priority, tag, message)
    }
}

// In Application.onCreate():
if (BuildConfig.DEBUG) {
    Timber.plant(Timber.DebugTree())
} else {
    Timber.plant(ReleaseTree())
}
```

```java
// VULNERABLE: Logging credentials
Log.d("Login", "Password: " + password);
Log.i("API", "Bearer " + token);

// SECURE: Use ProGuard/R8 to strip Log calls in release
// proguard-rules.pro:
// -assumenosideeffects class android.util.Log {
//     public static int d(...);
//     public static int v(...);
// }
```

**Detection regex:** `Log\.(d|v|i)\s*\(\s*"[^"]*"\s*,\s*[^)]*?(password|token|secret|key|credential|card|ssn|session)`
**Severity:** warning

## Gradle Build Security

### Dependency Vulnerabilities

Outdated dependencies introduce known CVEs. Use dependency verification (`gradle/verification-metadata.xml`) and keep versions current.

**Detection regex:** `(implementation|api|compile)\s+['"][^'"]+:[0-9]+\.[0-9]+`
**Severity:** warning

### Signing Configuration with Hardcoded Credentials

Keystore passwords in `build.gradle` are extractable. Load from environment variables or `local.properties` (excluded from VCS).

```groovy
// VULNERABLE: Hardcoded signing config
storePassword "mysecretpassword"
keyPassword "mykeypassword"

// SECURE: Environment variables
storePassword System.getenv("KEYSTORE_PASSWORD") ?: ""
keyPassword System.getenv("KEY_PASSWORD") ?: ""
```

**Detection regex:** `storePassword\s+["'][^"']+["']|keyPassword\s+["'][^"']+["']`
**Severity:** error

## Tapjacking and Overlay Attacks

### Missing Overlay Protection

Without `filterTouchesWhenObscured`, overlay apps can trick users into unintended actions. Add `android:filterTouchesWhenObscured="true"` on sensitive views or check `FLAG_WINDOW_IS_OBSCURED` in `onTouchEvent`.

**Detection regex:** `filterTouchesWhenObscured\s*=\s*"?true"?`
**Severity:** warning

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| Exported components without protection | Critical | Immediate | Low |
| SQL injection in ContentProvider | Critical | Immediate | Medium |
| WebView JavaScript interface exposure | Critical | Immediate | Medium |
| Hardcoded encryption keys | Critical | Immediate | Medium |
| Debug mode in release build | Critical | Immediate | Low |
| Cleartext traffic allowed | High | 1 week | Low |
| SharedPreferences without encryption | High | 1 week | Medium |
| Insecure random for tokens | High | 1 week | Low |
| Missing root detection | Medium | 1 month | High |
| Sensitive data in logs | Medium | 1 week | Low |
| allowBackup without exclusions | Medium | 1 week | Low |
| Missing certificate pinning | Medium | 1 month | Medium |
| Missing overlay protection | Low | 1 month | Low |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `cryptography-guide.md` — Cryptographic best practices
- `api-security.md` — API security patterns
- `authentication-patterns.md` — Authentication best practices
- `ios-sdk-security.md` — iOS security patterns (companion reference)

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Mobile SDK security coverage |
