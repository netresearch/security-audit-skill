# iOS SDK Security Patterns

Security patterns, common misconfigurations, and detection regexes for iOS applications. Covers Keychain misuse, App Transport Security, WebView risks, pasteboard leakage, insecure storage, URL scheme vulnerabilities, and cryptographic weaknesses.

## Keychain Security

### Insecure Keychain Accessibility

Using `kSecAttrAccessibleAlways` (deprecated in iOS 12) makes Keychain items accessible even when the device is locked, defeating the purpose of encrypted storage. Items are also available during device backups.

```swift
// VULNERABLE: kSecAttrAccessibleAlways — data accessible when device locked
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "auth_token",
    kSecValueData as String: tokenData,
    kSecAttrAccessible as String: kSecAttrAccessibleAlways
]
SecItemAdd(query as CFDictionary, nil)

// VULNERABLE: kSecAttrAccessibleAlwaysThisDeviceOnly — still accessible when locked
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "auth_token",
    kSecValueData as String: tokenData,
    kSecAttrAccessible as String: kSecAttrAccessibleAlwaysThisDeviceOnly
]
SecItemAdd(query as CFDictionary, nil)

// SECURE: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "auth_token",
    kSecValueData as String: tokenData,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
]
SecItemAdd(query as CFDictionary, nil)
```

**Detection regex (PCRE):** `kSecAttrAccessibleAlways(ThisDeviceOnly)?\b` — run with `grep -rnP`. Both `kSecAttrAccessibleAlways` and `kSecAttrAccessibleAlwaysThisDeviceOnly` are insecure because both keep the Keychain item accessible while the device is locked; the earlier pattern excluded the `…ThisDeviceOnly` variant that the VULNERABLE examples above show is also vulnerable.
**Severity:** error

### Missing Keychain Access Control

High-value secrets should require user presence via `SecAccessControlCreateWithFlags` with `.biometryCurrentSet` or passcode constraints. Use `kSecAttrAccessControl` in the Keychain query.

**Detection regex:** `SecItemAdd\s*\((?![\s\S]{0,300}kSecAttrAccessControl)`
**Severity:** warning

## App Transport Security (ATS)

### NSAllowsArbitraryLoads

Disabling ATS globally with `NSAllowsArbitraryLoads = YES` allows all HTTP connections, exposing the app to man-in-the-middle attacks. Apple requires justification for this setting during App Store review.

```xml
<!-- VULNERABLE: ATS disabled globally in Info.plist -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>

<!-- SECURE: ATS enabled with per-domain exceptions only -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>legacy-api.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
        </dict>
    </dict>
</dict>
```

```swift
// Code-level: Verify ATS is not disabled programmatically
// Check Info.plist at build time using a build phase script:
// if grep -q "NSAllowsArbitraryLoads.*true" "$INFOPLIST_FILE"; then
//     echo "error: NSAllowsArbitraryLoads must not be YES in release"
//     exit 1
// fi
```

**Detection regex:** `NSAllowsArbitraryLoads\s*</key>\s*<true\s*/?>|NSAllowsArbitraryLoads.*<true|NSAllowsArbitraryLoads\s*=\s*(YES|true)`
**Severity:** error

### Per-Domain ATS Exceptions Without Justification

Per-domain exceptions should be narrow, documented, and include `NSExceptionMinimumTLSVersion`. Wildcard exceptions are a red flag.

**Detection regex:** `NSExceptionAllowsInsecureHTTPLoads\s*</key>\s*<true`
**Severity:** warning

## WebView Security

### UIWebView Usage (Deprecated)

`UIWebView` is deprecated since iOS 12 and rejected by App Store since April 2020. It has known security issues including JavaScript-to-native bridge vulnerabilities and no content process isolation.

```swift
// VULNERABLE: UIWebView usage (deprecated)
import UIKit

class LegacyWebViewController: UIViewController {
    let webView = UIWebView()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.addSubview(webView)
        webView.loadRequest(URLRequest(url: URL(string: "https://example.com")!))
    }
}

// SECURE: Use WKWebView with proper configuration
import WebKit

class ModernWebViewController: UIViewController {
    lazy var webView: WKWebView = {
        let config = WKWebViewConfiguration()
        config.preferences.javaScriptEnabled = true
        config.defaultWebpagePreferences.allowsContentJavaScript = true
        let wv = WKWebView(frame: .zero, configuration: config)
        wv.navigationDelegate = self
        return wv
    }()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.addSubview(webView)
        webView.load(URLRequest(url: URL(string: "https://example.com")!))
    }
}
```

**Detection regex:** `UIWebView`
**Severity:** error

### WKWebView with Untrusted Content

Even with `WKWebView`, validate URLs against an allowlist and implement `WKNavigationDelegate` to restrict navigation to trusted origins.

**Detection regex:** `WKWebView[\s\S]{0,200}load\s*\(\s*URLRequest[\s\S]{0,100}(userURL|launchURL|deepLink|externalURL|untrusted)`
**Severity:** warning

## Pasteboard Security

### Sensitive Data on General Pasteboard

Data copied to the system `UIPasteboard.general` is accessible to all apps. On iOS 14+, users see a notification, but on older versions data is silently shared.

```swift
// VULNERABLE: Copying sensitive data to general pasteboard
func copyToken() {
    UIPasteboard.general.string = authToken
}

func copyPassword() {
    UIPasteboard.general.string = password
}

// SECURE: Use a named pasteboard with expiration
func copyTemporarySensitiveData(_ data: String) {
    let pasteboard = UIPasteboard.withUniqueName()
    pasteboard.setItems(
        [[UIPasteboard.typeAutomatic: data]],
        options: [
            .localOnly: true,
            .expirationDate: Date().addingTimeInterval(60) // Expires in 60 seconds
        ]
    )
}

// SECURE: Narrow the blast radius. There is no single "mark as
// sensitive" API on UIPasteboard — instead combine:
//   .localOnly        — don't propagate to other devices via Universal Clipboard
//   .expirationDate   — clear after N seconds
//   …and declare the type explicitly via UIPasteboard.typeListString /
//   UIPasteboard.typeAutomatic so the system Pasteboard suggestions
//   (iOS 14+) can drop the item from the "recent items" UI when
//   appropriate.
// For a password-field-like flow, use a UITextField with
// `isSecureTextEntry = true` and avoid writing to the pasteboard at
// all; the keyboard's native "Strong Password" integration is safer.
func copyWithShortLifetime(_ data: String) {
    let item = [UIPasteboard.typeAutomatic: data]
    UIPasteboard.general.setItems(
        [item],
        options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(120)]
    )
}
```

**Detection regex:** `UIPasteboard\.general\.(string|strings|items|setString|setValue|setItems)\s*=?\s*[\s\S]{0,60}(token|password|secret|key|credential|session|auth)`
**Severity:** warning

## Insecure Data Storage

### NSUserDefaults for Sensitive Data

`NSUserDefaults` / `UserDefaults` stores data in an unencrypted plist file in the app sandbox. On jailbroken devices or via backup extraction, this data is trivially readable.

```swift
// VULNERABLE: Storing tokens in UserDefaults
func saveSession(token: String, refreshToken: String) {
    UserDefaults.standard.set(token, forKey: "auth_token")
    UserDefaults.standard.set(refreshToken, forKey: "refresh_token")
}

// VULNERABLE: Storing password in UserDefaults
UserDefaults.standard.set(password, forKey: "user_password")

// SECURE: Use Keychain for sensitive data
func saveSession(token: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "auth_token",
        kSecValueData as String: token.data(using: .utf8)!,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    SecItemDelete(query as CFDictionary) // Remove old entry
    SecItemAdd(query as CFDictionary, nil)
}
```

**Detection regex:** `UserDefaults\.(standard\.)?set\s*\([^,]+,\s*forKey:\s*"(token|password|secret|key|credential|session|auth|refresh|api_key)|NSUserDefaults.*set(Object|Value).*forKey.*@"(token|password|secret|key|credential|session|auth)`
**Severity:** error

### Core Data Without Encryption

Core Data uses unencrypted SQLite by default. For sensitive models, set `NSPersistentStoreFileProtectionKey` to `FileProtectionType.complete`.

**Detection regex:** `NSPersistentContainer\s*\(name:|NSPersistentStoreDescription\s*\(\s*\)`
**Severity:** warning

## URL Scheme Vulnerabilities

### Custom URL Scheme Without Validation

Custom URL schemes (e.g., `myapp://`) can be invoked by any app or website. Without validating the source and parameters, attackers can trigger actions or inject data.

```swift
// VULNERABLE: No validation of URL scheme parameters
func application(_ app: UIApplication, open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
    if url.scheme == "myapp" {
        let token = url.queryParameters["token"]
        AuthManager.shared.setToken(token!) // Blindly trusting URL param
        return true
    }
    return false
}

// SECURE: Validate source application and parameters
func application(_ app: UIApplication, open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
    guard url.scheme == "myapp" else { return false }

    // Check source application
    let sourceApp = options[.sourceApplication] as? String ?? ""
    let allowedApps = ["com.example.trustedapp", "com.apple.SafariViewService"]
    guard allowedApps.contains(sourceApp) else {
        Logger.warning("URL scheme invoked from untrusted app: \(sourceApp)")
        return false
    }

    // Validate and sanitize parameters
    guard let host = url.host, host == "auth" else { return false }
    guard let token = url.queryParameters["token"],
          token.count <= 256,
          token.range(of: #"^[a-zA-Z0-9\-_]+$"#, options: .regularExpression) != nil else {
        return false
    }

    AuthManager.shared.setToken(token)
    return true
}
```

**Detection regex:** `application\s*\(\s*_\s+app.*open\s+url:\s*URL|openURL:\s*\(NSURL\s*\*\)`
**Severity:** warning

### Universal Link Bypass

Custom URL schemes can be hijacked. Use Universal Links (Associated Domains) for authentication callbacks, which provide server-verified deep linking.

**Detection regex:** `CFBundleURLSchemes|CFBundleURLTypes`
**Severity:** warning

## Jailbreak Detection

### Missing or Weak Jailbreak Detection

Apps processing sensitive data should detect jailbroken devices. Simple file-existence checks are easily bypassed by hooking frameworks like Frida or Substrate.

```swift
// BASIC (easily bypassed): Simple file check
func isJailbroken() -> Bool {
    let paths = [
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash", "/usr/sbin/sshd", "/etc/apt",
        "/private/var/lib/apt/"
    ]
    return paths.contains { FileManager.default.fileExists(atPath: $0) }
}

// SECURE: Multi-layered detection with runtime checks
class JailbreakDetector {
    static func isCompromised() -> Bool {
        // 1. File system checks
        if checkSuspiciousFiles() { return true }

        // 2. Sandbox integrity check
        if checkSandboxViolation() { return true }

        // 3. Dynamic library injection check
        if checkDyldInjection() { return true }

        // 4. Fork check (sandbox should prevent fork)
        if checkForkAvailability() { return true }

        return false
    }

    private static func checkSuspiciousFiles() -> Bool {
        let paths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash", "/usr/sbin/sshd", "/etc/apt",
            "/usr/bin/ssh", "/private/var/lib/apt/",
            "/private/var/lib/cydia", "/private/var/stash"
        ]
        for path in paths {
            if FileManager.default.fileExists(atPath: path) { return true }
            // Also try to open — hook might hide from fileExists
            if let _ = fopen(path, "r") { return true }
        }
        return false
    }

    private static func checkSandboxViolation() -> Bool {
        let testPath = "/private/jb_test_\(UUID().uuidString)"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true // Should not be able to write outside sandbox
        } catch {
            return false
        }
    }

    private static func checkDyldInjection() -> Bool {
        let count = _dyld_image_count()
        for i in 0..<count {
            guard let name = _dyld_get_image_name(i) else { continue }
            let imageName = String(cString: name)
            if imageName.contains("MobileSubstrate") ||
               imageName.contains("cycript") ||
               imageName.contains("frida") ||
               imageName.contains("SSLKillSwitch") {
                return true
            }
        }
        return false
    }

    private static func checkForkAvailability() -> Bool {
        let pid = fork()
        if pid >= 0 {
            // fork succeeded — jailbroken (sandbox should block this)
            if pid > 0 { kill(pid, SIGTERM) }
            return true
        }
        return false
    }
}
```

**Detection regex:** `(isJailbroken|jailbreakDetect|checkJailbreak|JailbreakDetector|Cydia\.app)`
**Severity:** warning

## Cryptographic Weaknesses

### Insecure Random Number Generation

The classically-insecure libc `random()`, `rand()`, and `srand()` are predictable and must not be used for security tokens. On Apple platforms `arc4random` and `arc4random_uniform` are actually backed by a CSPRNG (since they were rewritten in the 2010s to call into the kernel), so in practice they are cryptographically suitable — the failure mode to audit for here is `random()` / `rand()` / `srand()` with security-sensitive values. `SecRandomCopyBytes` remains the documented, API-stable way to request CSPRNG bytes.

```swift
// VULNERABLE: libc random() / rand() for session ID — predictable PRNG.
func generateSessionId() -> String {
    return String(format: "%08x%08x", random(), random())
}

// SECURE: SecRandomCopyBytes for cryptographic randomness
func generateToken() -> String {
    var bytes = [UInt8](repeating: 0, count: 32)
    let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    guard status == errSecSuccess else {
        fatalError("Failed to generate random bytes")
    }
    return Data(bytes).base64EncodedString()
}
```

**Detection regex (PCRE — target the classically-insecure libc PRNG, not arc4random which is CSPRNG on Apple):** `\b(random|rand|srand)\s*\([\s\S]{0,80}(token|key|secret|session|nonce|salt|iv)` — run with `grep -rnP` across `.swift`, `.m`, `.mm`. Match on `arc4random_uniform(…secret…)` is informational only: the function is suitable for cryptographic use on Apple platforms.
**Severity:** error

### Weak Hashing Algorithms

Using MD5 or SHA-1 for integrity checks or password hashing provides inadequate collision resistance.

```swift
// VULNERABLE: MD5 for integrity
import CommonCrypto
func md5Hash(_ input: String) -> String {
    let data = Data(input.utf8)
    var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    data.withUnsafeBytes { CC_MD5($0.baseAddress, CC_LONG(data.count), &digest) }
    return digest.map { String(format: "%02x", $0) }.joined()
}

// SECURE: SHA-256 using CryptoKit
import CryptoKit
func sha256Hash(_ input: String) -> String {
    let digest = SHA256.hash(data: Data(input.utf8))
    return digest.map { String(format: "%02x", $0) }.joined()
}
```

**Detection regex:** `CC_MD5\s*\(|CC_SHA1\s*\(|CC_MD5_DIGEST_LENGTH|kCCHmacAlgMD5`
**Severity:** warning

## Binary Protections

### Missing PIE (Position Independent Executable)

Non-PIE binaries load at a fixed address, making them vulnerable to return-oriented programming (ROP) attacks. Modern Xcode enables PIE by default, but legacy or custom build settings may disable it.

```
# Check binary for PIE flag:
# otool -hv MyApp | grep PIE
# If "PIE" is absent, the binary is not position-independent.

# In Xcode build settings, ensure:
# Generate Position-Dependent Code = No
# Other Linker Flags includes -pie (usually automatic)
```

```swift
// Xcode project.pbxproj — VULNERABLE: PIE disabled
// GCC_GENERATE_POSITION_DEPENDENT_CODE = YES;

// SECURE: Default Xcode setting
// GCC_GENERATE_POSITION_DEPENDENT_CODE = NO;
```

**Detection regex:** `GCC_GENERATE_POSITION_DEPENDENT_CODE\s*=\s*YES`
**Severity:** error

### Missing ARC (Automatic Reference Counting)

Non-ARC code is prone to use-after-free and double-free. Ensure `CLANG_ENABLE_OBJC_ARC = YES` in build settings.

**Detection regex:** `CLANG_ENABLE_OBJC_ARC\s*=\s*NO|\[(\w+)\s+release\]|\[(\w+)\s+autorelease\]`
**Severity:** error

## Logging and Debug Output

### NSLog with Sensitive Data

`NSLog` output persists in the device console log and can be read by other apps (on older iOS) or via device management profiles. Use `os_log` with appropriate privacy levels instead.

```swift
// VULNERABLE: NSLog/print with sensitive data
NSLog("Auth token: %@", authToken)
print("User password: \(password)")
debugPrint("API key: \(apiKey)")

// SECURE: os_log with private annotation
import os.log

let logger = Logger(subsystem: "com.example.app", category: "auth")
logger.debug("Auth completed for user: \(userID, privacy: .public)")
logger.debug("Token: \(authToken, privacy: .private)")
// In release: private values redacted as <private>
```

**Detection regex:** `NSLog\s*\(\s*@?"[^"]*%([@dfs])[^"]*"\s*,\s*[^)]*?(password|token|secret|key|credential|session|auth)|print\s*\(\s*"[^"]*\\?\(\s*(password|token|secret|key|credential|session|auth)`
**Severity:** warning

## Third-Party SDK Security

### Embedded Frameworks Without Verification

Verify binary framework integrity with checksums (`shasum -a 256`) and enable Library Validation in Hardened Runtime settings.

**Detection regex:** `\.framework|\.xcframework`
**Severity:** warning

## Screenshot and Background Snapshot Protection

### Sensitive Screens Captured in App Switcher

iOS captures screenshots when backgrounding. Add a blur overlay on `willResignActiveNotification` and remove it on `didBecomeActiveNotification` to protect sensitive screens.

**Detection regex:** `willResignActiveNotification[\s\S]{0,200}(blur|hide|overlay|mask|obscure)|applicationWillResignActive[\s\S]{0,200}(blur|hide|overlay)`
**Severity:** warning

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| kSecAttrAccessibleAlways usage | Critical | Immediate | Low |
| NSAllowsArbitraryLoads = YES | Critical | Immediate | Low |
| UIWebView usage | Critical | Immediate | High |
| Sensitive data in UserDefaults | Critical | Immediate | Medium |
| Missing PIE / ARC disabled | Critical | Immediate | Medium |
| Insecure random for tokens | High | 1 week | Low |
| Custom URL scheme without validation | High | 1 week | Medium |
| Pasteboard leaking sensitive data | Medium | 1 week | Low |
| Missing jailbreak detection | Medium | 1 month | High |
| NSLog with sensitive data | Medium | 1 week | Low |
| Missing screenshot protection | Low | 1 month | Medium |
| Missing Keychain access control | Low | 1 month | Medium |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `cryptography-guide.md` — Cryptographic best practices
- `api-security.md` — API security patterns
- `authentication-patterns.md` — Authentication best practices
- `android-sdk-security.md` — Android security patterns (companion reference)

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Mobile SDK security coverage |
