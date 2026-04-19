# Next.js Security Patterns

Security patterns, common misconfigurations, and detection regexes for Next.js applications. Next.js introduces unique security considerations through its hybrid rendering model (SSR, SSG, ISR), Server Components, Server Actions, API routes, and middleware. Many vulnerabilities arise from the blurred boundary between server and client code.

---

## Authentication & Authorization

### SA-NEXT-01: Server Action Auth Bypass

Server Actions are client-callable RPC endpoints. Without explicit authentication and authorization checks inside each action, any client can invoke them directly, bypassing UI-level guards.

```typescript
// VULNERABLE: No auth check in server action
'use server';

import { db } from '@/lib/db';

export async function deleteUser(userId: string) {
  // Anyone can call this action from the client!
  await db.user.delete({ where: { id: userId } });
  return { success: true };
}

// VULNERABLE: Only checking role on the client side
'use server';

export async function promoteToAdmin(userId: string) {
  await db.user.update({
    where: { id: userId },
    data: { role: 'admin' },
  });
}

// VULNERABLE: No input validation
'use server';

export async function updateProfile(formData: FormData) {
  const name = formData.get('name') as string;
  const email = formData.get('email') as string;
  await db.user.update({
    where: { id: formData.get('userId') as string },
    data: { name, email }, // userId from client = IDOR vulnerability
  });
}
```

```typescript
// SECURE: Auth + authorization check inside every server action
'use server';

import { auth } from '@/lib/auth';
import { db } from '@/lib/db';
import { z } from 'zod';

const deleteUserSchema = z.object({ userId: z.string().uuid() });

export async function deleteUser(userId: string) {
  const session = await auth();
  if (!session?.user) throw new Error('Unauthorized');
  if (session.user.role !== 'admin') throw new Error('Forbidden');

  const parsed = deleteUserSchema.parse({ userId });
  await db.user.delete({ where: { id: parsed.userId } });
  revalidatePath('/admin/users');
  return { success: true };
}

// SECURE: Validate ownership, not just authentication
'use server';

export async function updateProfile(formData: FormData) {
  const session = await auth();
  if (!session?.user) throw new Error('Unauthorized');

  const name = z.string().min(1).max(100).parse(formData.get('name'));
  const email = z.string().email().parse(formData.get('email'));

  // Use session userId, NOT client-provided userId
  await db.user.update({
    where: { id: session.user.id },
    data: { name, email },
  });
}
```

**Detection regex:** `'use server'[\s\S]*?export\s+async\s+function\s+\w+`
**Severity:** warning

---

### SA-NEXT-02: API Route Auth Bypass

Next.js API routes (both Pages Router `pages/api/` and App Router `app/api/*/route.ts`) are publicly accessible HTTP endpoints. Missing authentication middleware leaves them open to unauthorized access.

```typescript
// VULNERABLE: No auth in API route (App Router)
// app/api/users/route.ts
import { db } from '@/lib/db';
import { NextResponse } from 'next/server';

export async function GET() {
  const users = await db.user.findMany();
  return NextResponse.json(users); // anyone can list all users
}

export async function DELETE(request: Request) {
  const { userId } = await request.json();
  await db.user.delete({ where: { id: userId } });
  return NextResponse.json({ success: true });
}

// VULNERABLE: No auth in Pages Router API route
// pages/api/admin/settings.ts
export default async function handler(req, res) {
  if (req.method === 'POST') {
    await updateSettings(req.body);
    res.json({ success: true });
  }
}
```

```typescript
// SECURE: Auth check in API route
// app/api/users/route.ts
import { auth } from '@/lib/auth';
import { db } from '@/lib/db';
import { NextResponse } from 'next/server';

export async function GET() {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  if (session.user.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }

  const users = await db.user.findMany({
    select: { id: true, name: true, email: true },
  });
  return NextResponse.json(users);
}

// SECURE: Middleware-based auth for all API routes
// middleware.ts
import { auth } from '@/lib/auth';
import { NextResponse } from 'next/server';

export async function middleware(request) {
  const session = await auth();
  if (!session && request.nextUrl.pathname.startsWith('/api/admin')) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  return NextResponse.next();
}

export const config = {
  matcher: ['/api/admin/:path*'],
};
```

**Detection regex:** `export\s+async\s+function\s+(GET|POST|PUT|DELETE|PATCH)\s*\(`
**Severity:** warning

---

## Data Exposure

### SA-NEXT-03: Environment Variable Leakage (NEXT_PUBLIC_*)

Next.js exposes any environment variable prefixed with `NEXT_PUBLIC_` to the client bundle. Accidentally prefixing secrets with `NEXT_PUBLIC_` exposes them to every visitor.

```bash
# VULNERABLE: .env file with secrets exposed to client
NEXT_PUBLIC_DATABASE_URL=postgres://user:password@host/db
NEXT_PUBLIC_API_SECRET=sk_live_abc123xyz
NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_def456
NEXT_PUBLIC_JWT_SECRET=my-super-secret-jwt-key
NEXT_PUBLIC_AWS_SECRET_ACCESS_KEY=AKIA1234567890
```

```typescript
// VULNERABLE: Using NEXT_PUBLIC_ for server-only values
const apiClient = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL,
  headers: {
    Authorization: `Bearer ${process.env.NEXT_PUBLIC_API_SECRET}`,
  },
});
```

```bash
# SECURE: Only public, non-sensitive values get NEXT_PUBLIC_ prefix
NEXT_PUBLIC_APP_URL=https://myapp.com
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_abc123
NEXT_PUBLIC_GA_TRACKING_ID=G-XXXXXXXXXX

# Server-only secrets — no NEXT_PUBLIC_ prefix
DATABASE_URL=postgres://user:password@host/db
API_SECRET=sk_live_abc123xyz
STRIPE_SECRET_KEY=sk_live_def456
JWT_SECRET=my-super-secret-jwt-key
```

```typescript
// SECURE: Access secrets only in server-side code
// lib/stripe.ts (server only)
import Stripe from 'stripe';

export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2024-04-10',
});

// Validate env vars at build time
import { z } from 'zod';

const envSchema = z.object({
  DATABASE_URL: z.string().url(),
  STRIPE_SECRET_KEY: z.string().startsWith('sk_'),
  NEXT_PUBLIC_APP_URL: z.string().url(),
});

export const env = envSchema.parse(process.env);
```

**Detection regex:** `NEXT_PUBLIC_[A-Z_]*(SECRET|KEY|PASSWORD|TOKEN|CREDENTIAL|PRIVATE|DATABASE)`
**Severity:** error

---

### SA-NEXT-04: Server Component Data Over-Exposure

Server Components and `getServerSideProps` can access databases and internal services directly. Returning more data than the client needs exposes sensitive fields in the page payload (visible in `__NEXT_DATA__` or RSC payload).

```typescript
// VULNERABLE: getServerSideProps returns full database record
// pages/user/[id].tsx
export async function getServerSideProps({ params }) {
  const user = await db.user.findUnique({ where: { id: params.id } });
  return { props: { user } };
  // user includes: passwordHash, ssn, internalNotes, salary
}

// VULNERABLE: Server component passes full object to client
// app/dashboard/page.tsx
import ClientDashboard from './ClientDashboard';

export default async function DashboardPage() {
  const analytics = await db.analytics.findMany();
  // analytics includes internal metrics, cost data, revenue
  return <ClientDashboard data={analytics} />;
}

// VULNERABLE: API key in page props via getServerSideProps
export async function getServerSideProps() {
  const data = await fetch('https://api.internal.com/data', {
    headers: { Authorization: `Bearer ${process.env.INTERNAL_API_KEY}` },
  }).then((r) => r.json());

  return { props: { data, apiKey: process.env.INTERNAL_API_KEY } };
}
```

```typescript
// SECURE: Select only needed fields
export async function getServerSideProps({ params }) {
  const user = await db.user.findUnique({
    where: { id: params.id },
    select: { id: true, name: true, bio: true, avatarUrl: true },
  });
  if (!user) return { notFound: true };
  return { props: { user } };
}

// SECURE: Transform data before passing to client
export default async function DashboardPage() {
  const analytics = await db.analytics.findMany();
  const clientData = analytics.map(({ pageViews, uniqueVisitors, date }) => ({
    pageViews,
    uniqueVisitors,
    date: date.toISOString(),
  }));
  return <ClientDashboard data={clientData} />;
}

// SECURE: Never pass API keys to client
export async function getServerSideProps() {
  const data = await fetch('https://api.internal.com/data', {
    headers: { Authorization: `Bearer ${process.env.INTERNAL_API_KEY}` },
  }).then((r) => r.json());

  return { props: { data } }; // only data, no secrets
}
```

**Detection regex:** `(getServerSideProps|getStaticProps)[\s\S]*?return\s*\{\s*props:\s*\{[^}]*(password|secret|token|key|hash|ssn)`
**Severity:** warning

---

### SA-NEXT-05: Image Optimization SSRF via next/image

The `next/image` component proxies and optimizes external images through `/_next/image`. If the `remotePatterns` or `domains` configuration is overly permissive, attackers can use it as an SSRF proxy to access internal services.

```typescript
// VULNERABLE: Wildcard remote patterns allow any domain
// next.config.js
module.exports = {
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: '**' }, // allows ANY external domain
    ],
  },
};

// VULNERABLE: User-controlled image src without validation
function UserAvatar({ imageUrl }) {
  return <Image src={imageUrl} width={100} height={100} alt="avatar" />;
  // Attacker can pass: http://169.254.169.254/latest/meta-data/
}

// VULNERABLE: Overly broad domain list
module.exports = {
  images: {
    domains: ['*'], // deprecated but still works — allows everything
  },
};
```

```typescript
// SECURE: Strict remote patterns with specific hostnames
// next.config.js
module.exports = {
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'images.mycdn.com',
        pathname: '/uploads/**',
      },
      {
        protocol: 'https',
        hostname: 'avatars.githubusercontent.com',
      },
    ],
  },
};

// SECURE: Validate image URLs before rendering
import { isAllowedImageHost } from '@/lib/validation';

function UserAvatar({ imageUrl }) {
  const safeSrc = isAllowedImageHost(imageUrl) ? imageUrl : '/default-avatar.png';
  return <Image src={safeSrc} width={100} height={100} alt="avatar" />;
}

function isAllowedImageHost(url: string): boolean {
  try {
    const parsed = new URL(url);
    const allowedHosts = ['images.mycdn.com', 'avatars.githubusercontent.com'];
    return parsed.protocol === 'https:' && allowedHosts.includes(parsed.hostname);
  } catch {
    return false;
  }
}
```

**Detection regex:** `hostname:\s*['"]?\*{1,2}['"]?`
**Severity:** error

---

## Request Handling

### SA-NEXT-06: Open Redirect via Rewrites/Redirects

Next.js `rewrites` and `redirects` in `next.config.js` can create open redirect vulnerabilities when destination URLs include user-controlled path segments without validation.

```typescript
// VULNERABLE: User-controlled redirect destination
// next.config.js
module.exports = {
  async redirects() {
    return [
      {
        source: '/goto/:url*',
        destination: '/:url*', // open redirect to any path
        permanent: false,
      },
    ];
  },
};

// VULNERABLE: Open redirect in API route
// app/api/redirect/route.ts
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const target = searchParams.get('url');
  return Response.redirect(target!); // redirects to any URL
}

// VULNERABLE: Client-side redirect without validation
'use client';
import { useSearchParams, useRouter } from 'next/navigation';

function LoginCallback() {
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    const returnUrl = searchParams.get('returnUrl');
    router.push(returnUrl || '/'); // attacker: ?returnUrl=https://evil.com
  }, []);
}
```

```typescript
// SECURE: Validate redirect destinations
// app/api/redirect/route.ts
const ALLOWED_HOSTS = ['myapp.com', 'docs.myapp.com'];

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const target = searchParams.get('url') || '/';

  try {
    const parsed = new URL(target, 'https://myapp.com');
    if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
      return Response.redirect(new URL('/', request.url));
    }
    return Response.redirect(parsed.toString());
  } catch {
    return Response.redirect(new URL('/', request.url));
  }
}

// SECURE: Only allow relative paths for client redirects
function LoginCallback() {
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    const returnUrl = searchParams.get('returnUrl') || '/';
    // Only allow relative paths starting with /
    if (returnUrl.startsWith('/') && !returnUrl.startsWith('//')) {
      router.push(returnUrl);
    } else {
      router.push('/');
    }
  }, []);
}

// SECURE: Static redirects in next.config.js
module.exports = {
  async redirects() {
    return [
      {
        source: '/old-blog/:slug',
        destination: '/blog/:slug',
        permanent: true,
      },
    ];
  },
};
```

**Detection regex:** `Response\.redirect\s*\([^)]*searchParams|redirect\s*\(\s*(?:req|request)`
**Severity:** warning

---

### SA-NEXT-07: Server Component Data Serialization Leaks

When Server Components render, their output is serialized as an RSC payload sent to the client. If a server component accidentally includes sensitive data in its render output (even in comments or hidden elements), it becomes visible in the network response.

```typescript
// VULNERABLE: Sensitive data in server component output
// app/admin/page.tsx (server component)
export default async function AdminPage() {
  const config = await getServerConfig();
  // config includes: dbConnectionString, apiKeys, internalEndpoints
  return (
    <div>
      {/* Debug: {JSON.stringify(config)} */}
      <AdminDashboard />
    </div>
  );
}

// VULNERABLE: Hidden div with sensitive data
export default async function Page() {
  const user = await getCurrentUser();
  return (
    <>
      <div style={{ display: 'none' }} data-user={JSON.stringify(user)} />
      <PublicProfile name={user.name} />
    </>
  );
}

// VULNERABLE: Console.log in server component (logged but also serialized in dev)
export default async function Page() {
  const secrets = await getSecrets();
  console.log('Secrets:', secrets); // visible in server logs
  return <Dashboard />;
}
```

```typescript
// SECURE: Only render non-sensitive data
export default async function AdminPage() {
  const session = await auth();
  if (!session || session.user.role !== 'admin') {
    redirect('/login');
  }
  return <AdminDashboard />;
}

// SECURE: Pass only safe props to client components
export default async function Page() {
  const user = await getCurrentUser();
  return <PublicProfile name={user.name} avatarUrl={user.avatarUrl} />;
}

// SECURE: Use server-only package to prevent accidental client import
import 'server-only';

export async function getSecrets() {
  return {
    dbUrl: process.env.DATABASE_URL,
    apiKey: process.env.API_KEY,
  };
}
```

**Detection regex:** `JSON\.stringify\s*\([^)]*(config|secret|user|session|token|key|credential)`
**Severity:** warning

---

## CSRF & Caching

### SA-NEXT-08: Missing CSRF Protection on Mutation Endpoints

Next.js API routes that handle mutations (POST, PUT, DELETE) without CSRF protection are vulnerable to cross-site request forgery when using cookie-based authentication.

```typescript
// VULNERABLE: POST endpoint with cookie auth but no CSRF token
// app/api/transfer/route.ts
export async function POST(request: Request) {
  const session = await auth(); // reads auth cookie
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { amount, toAccount } = await request.json();
  await transferFunds(session.user.id, toAccount, amount);
  return NextResponse.json({ success: true });
}

// VULNERABLE: Form submission without CSRF token
// app/settings/page.tsx
export default function SettingsPage() {
  return (
    <form action="/api/settings" method="POST">
      <input name="email" type="email" />
      <button type="submit">Save</button>
    </form>
  );
}
```

```typescript
// SECURE: Use Server Actions (have built-in CSRF protection)
'use server';

import { auth } from '@/lib/auth';

export async function transferFunds(formData: FormData) {
  const session = await auth();
  if (!session) throw new Error('Unauthorized');

  const amount = Number(formData.get('amount'));
  const toAccount = formData.get('toAccount') as string;
  await processTransfer(session.user.id, toAccount, amount);
  revalidatePath('/dashboard');
}

// SECURE: CSRF token validation for API routes
// app/api/transfer/route.ts
import { validateCsrfToken } from '@/lib/csrf';

export async function POST(request: Request) {
  const csrfToken = request.headers.get('x-csrf-token');
  if (!validateCsrfToken(csrfToken)) {
    return NextResponse.json({ error: 'Invalid CSRF token' }, { status: 403 });
  }

  const session = await auth();
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { amount, toAccount } = await request.json();
  await transferFunds(session.user.id, toAccount, amount);
  return NextResponse.json({ success: true });
}

// SECURE: Use SameSite cookies + custom header check
// middleware.ts
export function middleware(request: NextRequest) {
  if (['POST', 'PUT', 'DELETE'].includes(request.method)) {
    const origin = request.headers.get('origin');
    const host = request.headers.get('host');
    if (origin && !origin.endsWith(host!)) {
      return NextResponse.json({ error: 'CSRF' }, { status: 403 });
    }
  }
  return NextResponse.next();
}
```

**Detection regex:** `export\s+async\s+function\s+POST\s*\([^)]*\)\s*\{[^}]*(?:cookie|session|auth)`
**Severity:** warning

---

### SA-NEXT-09: headers()/cookies() Misuse in Cached Routes

Using `headers()` or `cookies()` in statically cached routes creates a false sense of security. If a page is cached (ISR/SSG), the cached response is served to all users regardless of their cookies or headers, potentially exposing one user's data to another.

```typescript
// VULNERABLE: Using cookies in a cached page
// app/dashboard/page.tsx
export const revalidate = 3600; // cached for 1 hour

export default async function Dashboard() {
  const cookieStore = await cookies();
  const userId = cookieStore.get('userId')?.value;
  const data = await getUserData(userId);
  // First user's data is cached and served to ALL users for 1 hour!
  return <DashboardView data={data} />;
}

// VULNERABLE: generateStaticParams + user-specific data
export async function generateStaticParams() {
  return [{ slug: 'dashboard' }];
}

export default async function Page() {
  const headersList = await headers();
  const authToken = headersList.get('authorization');
  // Static page ignores auth token after first build
  const data = await fetchProtectedData(authToken);
  return <div>{data}</div>;
}
```

```typescript
// SECURE: Dynamic rendering for user-specific pages
// app/dashboard/page.tsx
export const dynamic = 'force-dynamic'; // never cache this page

export default async function Dashboard() {
  const cookieStore = await cookies();
  const userId = cookieStore.get('userId')?.value;
  if (!userId) redirect('/login');

  const data = await getUserData(userId);
  return <DashboardView data={data} />;
}

// SECURE: Use generateMetadata to opt into dynamic rendering
export async function generateMetadata() {
  const session = await auth(); // makes page dynamic
  return { title: `${session?.user.name}'s Dashboard` };
}

// SECURE: Cache public data, fetch private data client-side
export default async function Page() {
  const publicData = await getPublicStats(); // safe to cache
  return (
    <>
      <PublicStats data={publicData} />
      <Suspense fallback={<Spinner />}>
        <PrivateSection /> {/* fetches user data dynamically */}
      </Suspense>
    </>
  );
}
```

**Detection regex:** `revalidate\s*=\s*\d+[\s\S]*?(cookies|headers)\s*\(`
**Severity:** error

---

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-NEXT-01: Server Action auth bypass | Critical | Immediate | Medium |
| SA-NEXT-02: API route auth bypass | Critical | Immediate | Medium |
| SA-NEXT-03: NEXT_PUBLIC_ secret leakage | Critical | Immediate | Low |
| SA-NEXT-04: Server data over-exposure | High | 1 week | Medium |
| SA-NEXT-05: Image optimization SSRF | High | 1 week | Low |
| SA-NEXT-06: Open redirect via rewrites | Medium | 1 week | Low |
| SA-NEXT-07: Serialization data leaks | Medium | 1 month | Medium |
| SA-NEXT-08: Missing CSRF on mutations | High | 1 week | Medium |
| SA-NEXT-09: Cached route data leaks | Critical | Immediate | Medium |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `react-security.md` — React-specific patterns (underlying framework)
- `javascript-typescript-security-features.md` — Language-level patterns
- `frontend-security.md` — General frontend security patterns
- `api-security.md` — API security patterns

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 8 |
