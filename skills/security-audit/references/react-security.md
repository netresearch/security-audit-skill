# React Security Patterns

Security patterns, common misconfigurations, and detection regexes for React applications. React provides some built-in XSS protection through JSX auto-escaping, but developers can bypass these protections or introduce new vulnerability classes through unsafe APIs, unvetted dependencies, and improper state management.

---

## Cross-Site Scripting (XSS)

### SA-REACT-01: dangerouslySetInnerHTML Misuse

The `dangerouslySetInnerHTML` API bypasses React's built-in XSS protection by injecting raw HTML into the DOM. When used with unsanitized user input, it creates a direct XSS vector.

```jsx
// VULNERABLE: User input rendered as raw HTML
function Comment({ userComment }) {
  return (
    <div dangerouslySetInnerHTML={{ __html: userComment }} />
  );
}

// VULNERABLE: Fetched data rendered without sanitization
function Article({ content }) {
  return (
    <div dangerouslySetInnerHTML={{ __html: content }} />
  );
}

// VULNERABLE: Markdown-to-HTML conversion without sanitization
function MarkdownRenderer({ markdown }) {
  const html = marked(markdown); // raw HTML from user markdown
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
```

```jsx
// SECURE: Use a sanitization library before rendering
import DOMPurify from 'dompurify';

function Comment({ userComment }) {
  const sanitized = DOMPurify.sanitize(userComment);
  return (
    <div dangerouslySetInnerHTML={{ __html: sanitized }} />
  );
}

// SECURE: Use a React-aware markdown renderer
import ReactMarkdown from 'react-markdown';

function MarkdownRenderer({ markdown }) {
  return <ReactMarkdown>{markdown}</ReactMarkdown>;
}

// SECURE: Render text content directly (auto-escaped by React)
function Comment({ userComment }) {
  return <div>{userComment}</div>;
}
```

**Detection regex:** `dangerouslySetInnerHTML`
**Severity:** warning

---

### SA-REACT-02: JSX Expression Injection via User-Controlled Props

When user-controlled data flows into JSX props that accept React elements or render functions, attackers can inject arbitrary components or scripts. This is especially dangerous with spread operators and dynamic component rendering.

```jsx
// VULNERABLE: Spreading user-controlled object as props
function DynamicComponent({ userProps }) {
  return <div {...userProps} />;
}
// Attacker passes: { dangerouslySetInnerHTML: { __html: '<script>...' } }

// VULNERABLE: Dynamic component name from user input
function RenderComponent({ componentName, data }) {
  const Component = components[componentName];
  return <Component {...data} />;
}

// VULNERABLE: User-controlled ref callback
function Input({ onRef }) {
  return <input ref={onRef} />;
}
```

```jsx
// SECURE: Whitelist allowed props
function DynamicComponent({ userProps }) {
  const allowedProps = ['className', 'id', 'title', 'aria-label'];
  const safeProps = Object.fromEntries(
    Object.entries(userProps).filter(([key]) => allowedProps.includes(key))
  );
  return <div {...safeProps} />;
}

// SECURE: Whitelist allowed components
const ALLOWED_COMPONENTS = { Alert, Card, Badge };

function RenderComponent({ componentName, data }) {
  const Component = ALLOWED_COMPONENTS[componentName];
  if (!Component) return null;
  return <Component {...data} />;
}

// SECURE: Use controlled ref pattern
function Input({ inputRef }) {
  return <input ref={inputRef} />;
}
```

**Detection regex:** `\{\s*\.\.\.(?:user|props|data|input|params|query)`
**Severity:** warning

---

### SA-REACT-03: javascript: Protocol in href

React does not block `javascript:` URIs in `href` attributes. When user-controlled data is used as an `href`, attackers can inject `javascript:` URLs to execute arbitrary code when the link is clicked.

```jsx
// VULNERABLE: User-controlled href without validation
function UserLink({ url }) {
  return <a href={url}>Click here</a>;
}
// Attacker passes: "javascript:alert(document.cookie)"

// VULNERABLE: href from API response
function ExternalLink({ link }) {
  return <a href={link.url}>{link.label}</a>;
}

// VULNERABLE: Dynamic href construction
function ProfileLink({ userId, redirect }) {
  return <a href={redirect || `/user/${userId}`}>Profile</a>;
}
```

```jsx
// SECURE: Validate URL protocol with allowlist
function UserLink({ url }) {
  const safeUrl = sanitizeUrl(url);
  return <a href={safeUrl}>Click here</a>;
}

function sanitizeUrl(url) {
  try {
    const parsed = new URL(url, window.location.origin);
    if (['http:', 'https:', 'mailto:'].includes(parsed.protocol)) {
      return parsed.href;
    }
    return '#';
  } catch {
    return '#';
  }
}

// SECURE: Use a validated URL library
import { sanitizeUrl } from '@braintree/sanitize-url';

function ExternalLink({ link }) {
  return <a href={sanitizeUrl(link.url)}>{link.label}</a>;
}
```

**Detection regex:** `href\s*=\s*\{(?!['"]https?:)(?!['"]mailto:)(?!['"]/)`
**Severity:** warning

---

## Injection

### SA-REACT-04: Server Component vs Client Component Data Exposure

In React Server Components (RSC), props passed from server to client components are serialized and visible in the client bundle. Passing sensitive data (database records, auth tokens, internal IDs) as props to client components exposes them in the browser.

```jsx
// VULNERABLE: Passing full database record to client component
// ServerPage.jsx (server component)
import UserProfile from './UserProfile';

async function ServerPage() {
  const user = await db.users.findUnique({ where: { id: userId } });
  // user contains: { id, name, email, passwordHash, ssn, internalRole }
  return <UserProfile user={user} />;
}

// UserProfile.jsx
'use client';
export default function UserProfile({ user }) {
  // user.passwordHash and user.ssn are now in the client bundle!
  return <div>{user.name}</div>;
}

// VULNERABLE: Passing auth token to client component
async function Layout() {
  const session = await getSession();
  return <ClientNav session={session} />;
  // session.refreshToken is now exposed in the browser
}
```

```jsx
// SECURE: Select only needed fields before passing to client
async function ServerPage() {
  const user = await db.users.findUnique({
    where: { id: userId },
    select: { id: true, name: true, avatarUrl: true }
  });
  return <UserProfile user={user} />;
}

// SECURE: Create a DTO / sanitized object
async function Layout() {
  const session = await getSession();
  const clientSession = {
    userId: session.userId,
    displayName: session.displayName,
    expiresAt: session.expiresAt,
  };
  return <ClientNav session={clientSession} />;
}

// SECURE: Keep sensitive logic in server components
async function ServerPage() {
  const user = await db.users.findUnique({ where: { id: userId } });
  const isAdmin = user.internalRole === 'admin';
  return (
    <>
      <UserProfile name={user.name} avatarUrl={user.avatarUrl} />
      {isAdmin && <AdminPanel />}
    </>
  );
}
```

**Detection regex:** `'use client'[\s\S]*?\b(password|secret|token|ssn|creditCard|hash)\b`
**Severity:** warning

---

### SA-REACT-05: eval() and Function Constructor in Event Handlers

Using `eval()`, `new Function()`, or `setTimeout`/`setInterval` with string arguments in React components introduces code injection risks, especially when user input reaches these APIs.

```jsx
// VULNERABLE: eval in event handler
function Calculator({ expression }) {
  const handleCalculate = () => {
    const result = eval(expression);
    setResult(result);
  };
  return <button onClick={handleCalculate}>Calculate</button>;
}

// VULNERABLE: Function constructor with user input
function DynamicFilter({ filterCode }) {
  const filterFn = new Function('item', filterCode);
  const filtered = items.filter(filterFn);
  return <ItemList items={filtered} />;
}

// VULNERABLE: setTimeout with string argument
function DelayedAction({ action }) {
  useEffect(() => {
    setTimeout(action, 1000); // if action is a string, it's eval'd
  }, [action]);
}
```

```jsx
// SECURE: Use a math parser library instead of eval
import { evaluate } from 'mathjs';

function Calculator({ expression }) {
  const handleCalculate = () => {
    try {
      const result = evaluate(expression); // safe math-only parser
      setResult(result);
    } catch {
      setError('Invalid expression');
    }
  };
  return <button onClick={handleCalculate}>Calculate</button>;
}

// SECURE: Predefined filter functions
const FILTERS = {
  active: (item) => item.isActive,
  recent: (item) => item.createdAt > Date.now() - 86400000,
};

function DynamicFilter({ filterName }) {
  const filterFn = FILTERS[filterName] || (() => true);
  const filtered = items.filter(filterFn);
  return <ItemList items={filtered} />;
}

// SECURE: setTimeout with function reference
function DelayedAction({ onAction }) {
  useEffect(() => {
    const timer = setTimeout(() => onAction(), 1000);
    return () => clearTimeout(timer);
  }, [onAction]);
}
```

**Detection regex:** `\beval\s*\(|new\s+Function\s*\(`
**Severity:** error

---

## Authentication & Data Exposure

### SA-REACT-06: Sensitive Data in React State / Context

Storing sensitive data (tokens, passwords, PII) in React state or context makes it accessible through React DevTools and persisted in component tree snapshots. Any browser extension can read this data.

```jsx
// VULNERABLE: Auth token stored in React state
function AuthProvider({ children }) {
  const [authState, setAuthState] = useState({
    accessToken: null,
    refreshToken: null, // visible in React DevTools
    user: null,
  });

  return (
    <AuthContext.Provider value={authState}>
      {children}
    </AuthContext.Provider>
  );
}

// VULNERABLE: Credit card data in component state
function PaymentForm() {
  const [cardNumber, setCardNumber] = useState('');
  const [cvv, setCvv] = useState('');
  // Both visible in React DevTools, persisted in memory
  return (
    <form>
      <input value={cardNumber} onChange={(e) => setCardNumber(e.target.value)} />
      <input value={cvv} onChange={(e) => setCvv(e.target.value)} />
    </form>
  );
}

// VULNERABLE: Full user record with sensitive fields in context
const UserContext = createContext(null);

function UserProvider({ children }) {
  const [user, setUser] = useState(null); // includes ssn, dob, etc.
  return (
    <UserContext.Provider value={user}>
      {children}
    </UserContext.Provider>
  );
}
```

```jsx
// SECURE: Use httpOnly cookies for tokens (not accessible via JS)
function AuthProvider({ children }) {
  const [user, setUser] = useState(null); // only non-sensitive user info
  // Tokens stored in httpOnly cookies managed by the server
  // Auth requests include cookies automatically

  return (
    <AuthContext.Provider value={{ user, isAuthenticated: !!user }}>
      {children}
    </AuthContext.Provider>
  );
}

// SECURE: Use a PCI-compliant iframe for payment
function PaymentForm() {
  // Use Stripe Elements or similar — card data never touches React state
  return (
    <Elements stripe={stripePromise}>
      <CardElement />
    </Elements>
  );
}

// SECURE: Store only display-safe user fields in context
function UserProvider({ children }) {
  const [user, setUser] = useState(null);
  // Only: { id, displayName, email, avatarUrl }
  // Sensitive fields fetched on-demand via server API
  return (
    <UserContext.Provider value={user}>
      {children}
    </UserContext.Provider>
  );
}
```

**Detection regex:** `useState\s*\(\s*\{[^}]*(token|secret|password|refreshToken|cvv|ssn|creditCard)`
**Severity:** warning

---

### SA-REACT-07: Insecure useEffect Data Fetching

Fetching data in `useEffect` without proper auth headers, CSRF tokens, or error handling for auth failures can expose APIs to unauthorized access or leak error details to the client.

```jsx
// VULNERABLE: No auth header on protected API call
function Dashboard() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetch('/api/admin/users')
      .then((res) => res.json())
      .then(setData);
  }, []);

  return <UserList users={data} />;
}

// VULNERABLE: Token in URL query parameter (logged in server logs, browser history)
function Profile({ userId }) {
  useEffect(() => {
    fetch(`/api/user/${userId}?token=${localStorage.getItem('token')}`)
      .then((res) => res.json())
      .then(setProfile);
  }, [userId]);
}

// VULNERABLE: No error handling leaks auth state
function SecretData() {
  useEffect(() => {
    fetch('/api/secrets', {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        return res.json();
      })
      .then(setData)
      .catch((err) => setError(err.message)); // leaks HTTP status details
  }, []);
}
```

```jsx
// SECURE: Auth header via httpOnly cookie (automatic) or Authorization header
function Dashboard() {
  const [data, setData] = useState(null);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/admin/users', {
      credentials: 'same-origin', // sends httpOnly cookies
      headers: { 'Content-Type': 'application/json' },
    })
      .then((res) => {
        if (res.status === 401 || res.status === 403) {
          redirectToLogin();
          return;
        }
        if (!res.ok) throw new Error('Request failed');
        return res.json();
      })
      .then((json) => { if (!cancelled) setData(json); })
      .catch(() => { if (!cancelled) setError('Unable to load data'); });
    return () => { cancelled = true; };
  }, []);

  return <UserList users={data} />;
}

// SECURE: Use a data-fetching library with auth middleware
import useSWR from 'swr';

const fetcher = (url) =>
  fetch(url, { credentials: 'same-origin' }).then((res) => {
    if (!res.ok) throw new Error('Fetch failed');
    return res.json();
  });

function Profile({ userId }) {
  const { data, error } = useSWR(`/api/user/${userId}`, fetcher);
  if (error) return <div>Failed to load</div>;
  return <ProfileCard user={data} />;
}
```

**Detection regex:** `useEffect\s*\(\s*\(\)\s*=>\s*\{[^}]*fetch\s*\([^)]*\)\s*\.then`
**Severity:** warning

---

## Security Misconfiguration

### SA-REACT-08: Third-Party Component Risks (Unvetted npm Packages)

Using unvetted or unmaintained npm packages in React applications can introduce supply-chain vulnerabilities. Packages with postinstall scripts, excessive permissions, or known CVEs pose significant risks.

```jsx
// VULNERABLE: Using an unvetted rich text editor that injects scripts
import SketchyEditor from 'sketchy-wysiwyg-editor'; // 12 weekly downloads, no audits

function ContentEditor({ content, onChange }) {
  return <SketchyEditor value={content} onChange={onChange} />;
}

// VULNERABLE: Using a date picker with known prototype pollution
import DatePicker from 'abandoned-datepicker'; // last updated 4 years ago

function EventForm() {
  return <DatePicker onChange={handleDate} />;
}

// VULNERABLE: Importing a full utility library for one function
import _ from 'lodash'; // 4.7MB, large attack surface

function UserList({ users }) {
  const sorted = _.sortBy(users, 'name');
  return sorted.map((u) => <UserCard key={u.id} user={u} />);
}
```

```jsx
// SECURE: Use well-maintained, audited packages
import { EditorContent, useEditor } from '@tiptap/react';
import StarterKit from '@tiptap/starter-kit';

function ContentEditor({ content, onChange }) {
  const editor = useEditor({
    extensions: [StarterKit],
    content,
    onUpdate: ({ editor }) => onChange(editor.getHTML()),
  });
  return <EditorContent editor={editor} />;
}

// SECURE: Import only what you need (tree-shakeable)
import sortBy from 'lodash/sortBy';

function UserList({ users }) {
  const sorted = sortBy(users, 'name');
  return sorted.map((u) => <UserCard key={u.id} user={u} />);
}

// SECURE: Audit dependencies regularly
// package.json scripts:
// "audit": "npm audit --production",
// "audit:fix": "npm audit fix"
// Use: npm ls --all, socket.dev, or Snyk for deep analysis
```

**Detection regex:** `import\s+.*from\s+['"][^@./][^'"]*['"]`
**Severity:** info

---

### SA-REACT-09: Missing key Prop Leading to State Leaks Between Items

When React list items share keys or use array indices as keys, component state can leak between logically different items. This can cause one user's data to appear in another user's component instance after reordering.

```jsx
// VULNERABLE: Using array index as key with stateful components
function UserMessages({ messages }) {
  return messages.map((msg, index) => (
    <MessageEditor key={index} message={msg} />
    // If list reorders, editor state (draft text) leaks between items
  ));
}

// VULNERABLE: Non-unique keys cause state cross-contamination
function UserList({ users }) {
  return users.map((user) => (
    <UserCard key={user.department} user={user} />
    // Multiple users in same department share state
  ));
}

// VULNERABLE: Missing key prop entirely
function TodoList({ todos }) {
  return todos.map((todo) => (
    <TodoItem todo={todo} />
  ));
}
```

```jsx
// SECURE: Use stable, unique identifiers as keys
function UserMessages({ messages }) {
  return messages.map((msg) => (
    <MessageEditor key={msg.id} message={msg} />
  ));
}

// SECURE: Composite key for uniqueness
function UserList({ users }) {
  return users.map((user) => (
    <UserCard key={user.id} user={user} />
  ));
}

// SECURE: Always provide unique keys
function TodoList({ todos }) {
  return todos.map((todo) => (
    <TodoItem key={todo.id} todo={todo} />
  ));
}
```

**Detection regex:** `key\s*=\s*\{[^}]*(index|idx|i)\s*\}`
**Severity:** info

---

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-REACT-01: dangerouslySetInnerHTML XSS | High | Immediate | Low |
| SA-REACT-02: JSX expression injection via props | High | 1 week | Medium |
| SA-REACT-03: javascript: protocol in href | High | Immediate | Low |
| SA-REACT-04: Server/client component data exposure | Medium | 1 week | Medium |
| SA-REACT-05: eval/Function constructor injection | Critical | Immediate | Low |
| SA-REACT-06: Sensitive data in state/context | Medium | 1 week | Medium |
| SA-REACT-07: Insecure useEffect data fetching | Medium | 1 month | Medium |
| SA-REACT-08: Unvetted third-party packages | Medium | 1 month | High |
| SA-REACT-09: Missing/index key prop state leaks | Low | 1 month | Low |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `javascript-typescript-security-features.md` — Language-level patterns
- `frontend-security.md` — General frontend security patterns
- `supply-chain-security.md` — npm supply chain risks
- `nextjs-security.md` — Next.js-specific patterns (builds on React)

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Phase 8 |
