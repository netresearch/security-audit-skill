# Nuxt Security Patterns

Security patterns, common misconfigurations, and detection regexes for Nuxt 3 applications. Nuxt introduces unique security considerations through its auto-imports, hybrid rendering, Nitro server engine, and the boundary between server and client code. Many vulnerabilities arise from misconfigured runtime config, unprotected server routes, and SSR-specific XSS patterns.

---

## Authentication & Authorization

### SA-NUXT-01: Server Route Auth Bypass

Nitro server routes (`server/api/` and `server/routes/`) are publicly accessible HTTP endpoints. Without explicit auth middleware, any client can invoke them directly.

```typescript
// VULNERABLE: No auth check in server API route
// server/api/users.get.ts
export default defineEventHandler(async (event) => {
  const users = await db.user.findMany();
  return users; // anyone can list all users including sensitive fields
});

// VULNERABLE: Delete endpoint without auth
// server/api/users/[id].delete.ts
export default defineEventHandler(async (event) => {
  const id = getRouterParam(event, 'id');
  await db.user.delete({ where: { id } });
  return { success: true };
});

// VULNERABLE: Admin endpoint without role check
// server/api/admin/settings.post.ts
export default defineEventHandler(async (event) => {
  const body = await readBody(event);
  await updateSettings(body);
  return { success: true };
});
```

```typescript
// SECURE: Auth middleware applied to server routes
// server/middleware/auth.ts
export default defineEventHandler(async (event) => {
  const protectedPaths = ['/api/admin', '/api/users'];
  const path = getRequestURL(event).pathname;

  if (protectedPaths.some((p) => path.startsWith(p))) {
    const session = await getUserSession(event);
    if (!session?.user) {
      throw createError({ statusCode: 401, message: 'Unauthorized' });
    }
    event.context.user = session.user;
  }
});

// SECURE: Auth + role check in handler
// server/api/admin/settings.post.ts
export default defineEventHandler(async (event) => {
  const user = event.context.user;
  if (!user || user.role !== 'admin') {
    throw createError({ statusCode: 403, message: 'Forbidden' });
  }

  const body = await readValidatedBody(event, settingsSchema.parse);
  await updateSettings(body);
  return { success: true };
});

// SECURE: Input validation with zod
// server/api/users/[id].delete.ts
import { z } from 'zod';

export default defineEventHandler(async (event) => {
  const user = event.context.user;
  if (!user || user.role !== 'admin') {
    throw createError({ statusCode: 403, message: 'Forbidden' });
  }

  const id = z.string().uuid().parse(getRouterParam(event, 'id'));
  await db.user.delete({ where: { id } });
  return { success: true };
});
```

**Detection regex:** `defineEventHandler\s*\(\s*async\s*\(\s*event\s*\)`
**Severity:** warning

---

### SA-NUXT-07: Middleware Auth Patterns

Nuxt route middleware (`middleware/`) runs before page rendering but only on the client after initial SSR. Relying solely on client middleware for auth is insecure because server routes remain unprotected, and middleware can be bypassed via direct navigation.

```typescript
// VULNERABLE: Client-only middleware for auth
// middleware/auth.ts
export default defineNuxtRouteMiddleware((to, from) => {
  const { loggedIn } = useUserSession();
  if (!loggedIn.value) {
    return navigateTo('/login');
  }
  // Only runs in browser — server-side requests bypass this entirely
});

// VULNERABLE: Auth check that doesn't protect server data
// middleware/admin.ts
export default defineNuxtRouteMiddleware((to) => {
  const user = useUser();
  if (user.value?.role !== 'admin') {
    return navigateTo('/');
  }
  // Page data is still fetched on the server without auth check
});
```

```typescript
// SECURE: Server middleware for API protection + client middleware for UX
// server/middleware/auth.ts (protects API routes)
export default defineEventHandler(async (event) => {
  if (getRequestURL(event).pathname.startsWith('/api/protected')) {
    const session = await getUserSession(event);
    if (!session) {
      throw createError({ statusCode: 401, message: 'Unauthorized' });
    }
    event.context.user = session.user;
  }
});

// middleware/auth.ts (client UX redirect)
export default defineNuxtRouteMiddleware(async (to) => {
  const { loggedIn, fetch: fetchSession } = useUserSession();
  await fetchSession(); // re-verify session
  if (!loggedIn.value) {
    return navigateTo('/login');
  }
});

// SECURE: Global middleware with server-side auth
// middleware/auth.global.ts
export default defineNuxtRouteMiddleware(async (to) => {
  const protectedRoutes = ['/dashboard', '/admin', '/settings'];
  if (!protectedRoutes.some((r) => to.path.startsWith(r))) return;

  const { loggedIn } = useUserSession();
  if (!loggedIn.value) {
    return navigateTo(`/login?redirect=${encodeURIComponent(to.fullPath)}`);
  }
});
```

**Detection regex:** `defineNuxtRouteMiddleware\s*\(`
**Severity:** info

---

## Data Exposure

### SA-NUXT-02: useAsyncData / useFetch Data Exposure to Client

Data fetched with `useAsyncData` or `useFetch` in Nuxt pages and components is serialized and sent to the client as part of the hydration payload. Fetching sensitive server-side data through these composables exposes it in the HTML source.

```typescript
// VULNERABLE: Full user record including sensitive fields
// pages/admin/users.vue
<script setup>
const { data: users } = await useFetch('/api/admin/users');
// users includes: passwordHash, ssn, salary — all in HTML payload
</script>

<template>
  <div v-for="user in users" :key="user.id">
    {{ user.name }}
  </div>
</template>

// VULNERABLE: Internal API response with debug info
<script setup>
const { data } = await useAsyncData('config', () =>
  $fetch('/api/internal/config')
);
// config includes: dbConnectionString, apiKeys, debug flags
</script>

// VULNERABLE: Sensitive data in transform but still in payload
<script setup>
const { data } = await useFetch('/api/users/me', {
  transform: (user) => {
    // transform runs client-side too — raw data is in payload
    return { name: user.name };
  },
});
</script>
```

```typescript
// SECURE: Server API returns only needed fields
// server/api/admin/users.get.ts
export default defineEventHandler(async (event) => {
  const user = event.context.user;
  if (!user || user.role !== 'admin') {
    throw createError({ statusCode: 403 });
  }

  return await db.user.findMany({
    select: { id: true, name: true, email: true, role: true },
  });
});

// pages/admin/users.vue
<script setup>
const { data: users } = await useFetch('/api/admin/users');
// Only safe fields returned from API
</script>

// SECURE: Use server-only utils for sensitive operations
// server/utils/getFullUser.ts (never sent to client)
export async function getFullUser(id: string) {
  return await db.user.findUnique({ where: { id } });
}

// SECURE: pick option to limit payload fields
<script setup>
const { data } = await useFetch('/api/users/me', {
  pick: ['name', 'email', 'avatarUrl'],
});
</script>
```

**Detection regex:** `useFetch\s*\(\s*['"][^'"]*admin|useAsyncData\s*\(\s*['"][^'"]*secret`
**Severity:** warning

---

### SA-NUXT-03: runtimeConfig vs appConfig Secrets Leakage

Nuxt's `runtimeConfig` has a `public` key that is exposed to the client. Placing secrets in `runtimeConfig.public` or in `appConfig` (which is always public) exposes them to every visitor.

```typescript
// VULNERABLE: Secrets in public runtimeConfig
// nuxt.config.ts
export default defineNuxtConfig({
  runtimeConfig: {
    public: {
      apiSecret: 'sk_live_abc123',           // exposed to client!
      databaseUrl: 'postgres://user:pass@host/db', // exposed!
      stripeSecretKey: 'sk_live_def456',      // exposed!
    },
  },
});

// VULNERABLE: Secrets in appConfig (always public)
// app.config.ts
export default defineAppConfig({
  apiKey: 'sk_live_abc123', // always sent to client
  jwtSecret: 'my-secret',  // always sent to client
});

// VULNERABLE: Accessing private config in client component
// composables/useApi.ts
export function useApi() {
  const config = useRuntimeConfig();
  // config.secretApiKey is undefined on client but attempt reveals intent
  return $fetch('/api/data', {
    headers: { Authorization: config.public.apiSecret },
  });
}
```

```typescript
// SECURE: Private secrets in runtimeConfig root (server-only)
// nuxt.config.ts
export default defineNuxtConfig({
  runtimeConfig: {
    // Server-only (not exposed to client)
    databaseUrl: process.env.DATABASE_URL,
    stripeSecretKey: process.env.STRIPE_SECRET_KEY,
    jwtSecret: process.env.JWT_SECRET,

    // Client-safe public values
    public: {
      appUrl: process.env.APP_URL || 'https://myapp.com',
      stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY,
    },
  },
});

// SECURE: Access private config only in server routes
// server/api/payment.post.ts
export default defineEventHandler(async (event) => {
  const config = useRuntimeConfig(event);
  const stripe = new Stripe(config.stripeSecretKey); // server-only
  // ...
});

// SECURE: appConfig for non-sensitive UI configuration only
// app.config.ts
export default defineAppConfig({
  theme: { primaryColor: '#3b82f6' },
  ui: { rounded: 'lg' },
});
```

**Detection regex:** `runtimeConfig[\s\S]*?public\s*:\s*\{[^}]*(secret|password|token|key|credential|private|database)`
**Severity:** error

---

## Cross-Site Scripting (XSS)

### SA-NUXT-04: SSR-Specific XSS via v-html

The `v-html` directive renders raw HTML and bypasses Vue's auto-escaping. In SSR context, this is especially dangerous because the XSS payload is rendered into the initial HTML response, executing before any client-side framework code loads.

```vue
<!-- VULNERABLE: User input rendered as raw HTML -->
<template>
  <div v-html="userComment" />
</template>

<script setup>
const props = defineProps<{ userComment: string }>();
</script>

<!-- VULNERABLE: Markdown rendered without sanitization -->
<template>
  <article v-html="renderedMarkdown" />
</template>

<script setup>
import { marked } from 'marked';
const props = defineProps<{ content: string }>();
const renderedMarkdown = computed(() => marked(props.content));
</script>

<!-- VULNERABLE: CMS content rendered as HTML -->
<template>
  <div v-html="page.body" />
</template>

<script setup>
const { data: page } = await useFetch(`/api/pages/${route.params.slug}`);
</script>
```

```vue
<!-- SECURE: Use text interpolation (auto-escaped) -->
<template>
  <div>{{ userComment }}</div>
</template>

<!-- SECURE: Sanitize HTML before rendering -->
<template>
  <div v-html="sanitizedHtml" />
</template>

<script setup>
import DOMPurify from 'isomorphic-dompurify';

const props = defineProps<{ content: string }>();
const sanitizedHtml = computed(() => DOMPurify.sanitize(props.content));
</script>

<!-- SECURE: Use a Vue-aware markdown component -->
<template>
  <ContentRenderer :value="page" />
</template>

<script setup>
// Use @nuxt/content for safe markdown rendering
const { data: page } = await useAsyncData(() =>
  queryContent(route.params.slug).findOne()
);
</script>
```

**Detection regex:** `v-html\s*=`
**Severity:** warning

---

## Server Security

### SA-NUXT-05: Nitro Server Handler Security

Nitro server handlers have direct access to the Node.js runtime. Improper input handling in handlers can lead to path traversal, command injection, or denial of service.

```typescript
// VULNERABLE: Path traversal in file handler
// server/api/files/[...path].get.ts
import { readFileSync } from 'fs';
import { join } from 'path';

export default defineEventHandler((event) => {
  const filePath = getRouterParam(event, 'path');
  const content = readFileSync(join('/data', filePath!), 'utf-8');
  // Attacker: /api/files/../../etc/passwd
  return content;
});

// VULNERABLE: Command injection via query parameter
// server/api/ping.get.ts
import { exec } from 'child_process';

export default defineEventHandler((event) => {
  const host = getQuery(event).host;
  return new Promise((resolve) => {
    exec(`ping -c 1 ${host}`, (err, stdout) => {
      resolve(stdout);
    });
  });
});

// VULNERABLE: Unvalidated body used in database query
// server/api/search.post.ts
export default defineEventHandler(async (event) => {
  const { query } = await readBody(event);
  const results = await db.$queryRawUnsafe(`SELECT * FROM items WHERE name LIKE '%${query}%'`);
  return results;
});
```

```typescript
// SECURE: Validate and sanitize file paths
// server/api/files/[...path].get.ts
import { readFile } from 'fs/promises';
import { join, resolve, normalize } from 'path';

const DATA_DIR = resolve('/data');

export default defineEventHandler(async (event) => {
  const filePath = getRouterParam(event, 'path');
  if (!filePath) throw createError({ statusCode: 400 });

  const resolved = resolve(DATA_DIR, normalize(filePath));
  if (!resolved.startsWith(DATA_DIR)) {
    throw createError({ statusCode: 403, message: 'Access denied' });
  }

  try {
    const content = await readFile(resolved, 'utf-8');
    return content;
  } catch {
    throw createError({ statusCode: 404 });
  }
});

// SECURE: Use parameterized queries
// server/api/search.post.ts
export default defineEventHandler(async (event) => {
  const body = await readValidatedBody(event, searchSchema.parse);
  const results = await db.item.findMany({
    where: { name: { contains: body.query } },
    take: 50,
  });
  return results;
});

// SECURE: Avoid shell commands; use libraries
// server/api/ping.get.ts
import { isIP } from 'net';

export default defineEventHandler((event) => {
  const host = getQuery(event).host as string;
  if (!host || !isIP(host)) {
    throw createError({ statusCode: 400, message: 'Invalid host' });
  }
  // Use a network library instead of shell exec
  return { host, status: 'validated' };
});
```

**Detection regex:** `exec\s*\(|execSync\s*\(|\$queryRawUnsafe\s*\(`
**Severity:** error

---

## Configuration

### SA-NUXT-06: Plugin Execution Order Risks

Nuxt plugins execute in filesystem order by default. Security-critical plugins (auth initialization, CSRF setup) that depend on execution order can be bypassed if another plugin runs first and modifies global state.

```typescript
// VULNERABLE: Auth plugin relies on implicit order
// plugins/auth.ts (runs after analytics.ts alphabetically)
export default defineNuxtPlugin((nuxtApp) => {
  const { session } = useUserSession();
  // If analytics.ts already made API calls, they ran without auth
});

// VULNERABLE: CSRF plugin that might run too late
// plugins/csrf.ts
export default defineNuxtPlugin((nuxtApp) => {
  nuxtApp.hook('app:created', () => {
    const token = useCookie('csrf-token');
    // Other plugins may have already made fetch calls without CSRF
  });
});

// VULNERABLE: Plugin modifies global fetch without protection
// plugins/api.ts
export default defineNuxtPlugin(() => {
  globalThis.$fetch = $fetch.create({
    baseURL: '/api',
    // No auth headers — all API calls go unauthenticated
  });
});
```

```typescript
// SECURE: Explicit plugin ordering with enforce
// plugins/01.auth.ts
export default defineNuxtPlugin({
  name: 'auth',
  enforce: 'pre', // runs before other plugins
  async setup(nuxtApp) {
    const { fetch: fetchSession } = useUserSession();
    await fetchSession();
  },
});

// SECURE: Depend on named plugins
// plugins/02.api.ts
export default defineNuxtPlugin({
  name: 'api',
  dependsOn: ['auth'], // explicit dependency
  setup() {
    const { session } = useUserSession();
    const api = $fetch.create({
      baseURL: '/api',
      onRequest({ options }) {
        if (session.value?.token) {
          options.headers.set('Authorization', `Bearer ${session.value.token}`);
        }
      },
    });
    return { provide: { api } };
  },
});

// SECURE: Use numbered prefix for clear ordering
// plugins/00.csrf.ts
export default defineNuxtPlugin({
  name: 'csrf',
  enforce: 'pre',
  setup(nuxtApp) {
    const csrfToken = useCookie('csrf-token');
    nuxtApp.hook('app:created', () => {
      // CSRF setup runs before any other plugin
    });
  },
});
```

**Detection regex:** `defineNuxtPlugin\s*\(\s*(?:async\s*)?\(\s*nuxtApp\s*\)\s*=>`
**Severity:** info

---

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-NUXT-01: Server route auth bypass | Critical | Immediate | Medium |
| SA-NUXT-02: useAsyncData/useFetch data exposure | High | 1 week | Medium |
| SA-NUXT-03: runtimeConfig secrets leakage | Critical | Immediate | Low |
| SA-NUXT-04: v-html SSR XSS | High | Immediate | Low |
| SA-NUXT-05: Nitro handler injection | Critical | Immediate | Medium |
| SA-NUXT-06: Plugin execution order risks | Low | 1 month | Medium |
| SA-NUXT-07: Middleware auth patterns | Medium | 1 week | Medium |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `javascript-typescript-security-features.md` — Language-level patterns
- `frontend-security.md` — General frontend security patterns
- `nodejs-security-features.md` — Node.js runtime patterns
- `api-security.md` — API security patterns

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 8 |
