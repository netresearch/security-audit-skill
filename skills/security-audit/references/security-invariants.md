# Security Invariants as Runtime Assertions

Encode security guarantees as runtime checks in the code path, not only in tests. A test proves the guarantee held during the test run; an inline assertion proves it holds in production — and fails loudly when it doesn't.

## Why

A security test answers "did this case work?". A security invariant answers "is this guarantee still true right now?". The two are complementary: tests give coverage on known inputs; inline invariants catch the unknown ones (the bypass you didn't anticipate, the refactor that quietly broke the boundary, the AI-generated code path that "looks right").

Three properties make a security invariant pay off:

1. **Crystalline** — the rule has a yes/no answer at the point of check
2. **Boundary-local** — it can be evaluated at the entry/exit of a small piece of code
3. **Violation = bug** — if the assertion fails, the program is in an impossible state; failing closed is correct

If any one is missing, you want input validation, authorization middleware, or a typed API — not an invariant.

## Where to Use

| Domain | Invariant | Where to assert |
|--------|-----------|-----------------|
| Authorization boundary | "this branch only runs for principals with capability X" | First line of the sensitive function |
| Tenant isolation | "every row this query touches belongs to tenant T" | Before executing, after fetching |
| Principal binding | "the resource identified by id Y is owned by the current actor" | Between authorisation check and mutation |
| Capability checks | "this code path is unreachable for anonymous sessions" | Inside the branch |
| Redaction | "this response body contains no PII when the requester is unauthenticated" | Just before the response is serialised |
| Crypto state | "this key is only ever used with the cipher mode it was generated for" | At the use site, not at construction |
| Audit logging | "every mutation reaches the audit sink" | Postcondition on the service method |

## Where NOT to Use

- **External input** — that is validation. Return a typed error, do not panic. A user sending a malformed payload is not an impossible state.
- **Cross-service contracts** — assert on what *this* service controls, not what its dependencies returned. A downstream returning unexpected data is an error path, not an invariant violation.
- **Soft business rules** — "discount must not exceed 50%" is a domain rule that may legitimately change; it belongs in domain logic with proper errors, not an assertion.

Heuristic: if a violation could plausibly be caused by a malicious or buggy *caller*, it is validation. If it could only be caused by *this code* being wrong, it is an invariant.

## Patterns

### Authorization boundary

The invariant is "the authz decision was made before this line, and was positive".

```php
declare(strict_types=1);

public function deleteInvoice(int $invoiceId, User $actor): void
{
    if (!$this->authz->can($actor, 'invoice.delete', $invoiceId)) {
        throw new ForbiddenException();              // validation: caller's mistake
    }

    // From here on, authorisation is established. State the invariant.
    \assert(
        $this->authz->can($actor, 'invoice.delete', $invoiceId),
        sprintf('authz invariant violated: actor=%d invoice=%d', $actor->id, $invoiceId)
    );

    $this->repository->delete($invoiceId);
}
```

Why the assertion when the check is one line up: refactors split functions. The assertion at the mutation site keeps the guarantee local to the dangerous operation, so a later refactor that moves the authz check cannot silently weaken it.

### Tenant isolation

```go
// Contract:
//   pre: ctx carries a tenant ID
//   inv: every row touched belongs to that tenant
func (s *OrderService) ListForTenant(ctx context.Context) ([]Order, error) {
    tenantID, ok := TenantFromContext(ctx)
    if !ok || tenantID == "" {
        return nil, ErrNoTenant
    }

    rows, err := s.db.Query(ctx, "SELECT id, tenant_id, ... FROM orders WHERE tenant_id = $1", tenantID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var out []Order
    for rows.Next() {
        var o Order
        if err := rows.Scan(&o.ID, &o.TenantID /* ... */); err != nil {
            return nil, err
        }
        if o.TenantID != tenantID {
            // The WHERE clause should make this impossible. If we got here,
            // either the query was rewritten, or the column mapping drifted.
            panic(fmt.Sprintf("tenant invariant violated: want=%s got=%s", tenantID, o.TenantID))
        }
        out = append(out, o)
    }
    return out, rows.Err()
}
```

The check is cheap and the failure mode is catastrophic — exactly the case where in-band assertion earns its keep.

### Principal binding

```typescript
async function updateProfile(
    actor: AuthenticatedUser,
    profileId: string,
    patch: ProfilePatch,
): Promise<Profile> {
    const profile = await profiles.byId(profileId);
    if (profile.ownerId !== actor.id) {
        throw new ForbiddenError();
    }

    // Invariant: from here, profile.ownerId === actor.id
    if (profile.ownerId !== actor.id) {
        throw new InvariantViolation(
            `principal binding: actor=${actor.id} profile.owner=${profile.ownerId}`,
        );
    }

    return profiles.apply(profile, patch);
}
```

The duplicated check is intentional. The first is validation (user-facing error); the second is the inline guarantee that survives refactors and signals a code-path bug if it ever fires.

### Redaction postcondition

```python
def serialize_for(viewer: Viewer, doc: Document) -> dict:
    body = _serialise(doc)
    if not viewer.is_authenticated:
        body = _redact(body)

    # Postcondition: anonymous viewers never see PII fields.
    if not viewer.is_authenticated:
        assert "ssn" not in body and "email" not in body, \
            f"redaction invariant violated: leaked fields = {set(body) & {'ssn', 'email'}}"
    return body
```

## Implementation Notes

### Failing closed

A failing security invariant must crash the request, not log-and-continue. Catching the failure to "stay available" is exactly the path that turns a detectable bypass into a silent breach. Let the request die; the supervisor restarts the worker.

### Language idioms

| Language | Mechanism | Production behaviour |
|----------|-----------|----------------------|
| PHP | `assert()` with `zend.assertions=1` (dev/CI), `-1` (prod). For always-on: throw a custom `InvariantViolation` | Compile-out optional |
| Go | `if !cond { panic(...) }` or a helper; panic crosses goroutine boundary | Always-on; recover only at supervisor root |
| TypeScript/Node | `throw new InvariantViolation(...)` from a small helper | Always-on; surface as 500 with no detail |
| Python | `assert` (stripped with `-O`); for always-on use `if not cond: raise InvariantViolation` | Compile-out optional |
| Rust | `assert!`/`debug_assert!`; prefer the former for security invariants | Always-on (release builds keep `assert!`) |

For security invariants specifically, prefer **always-on** over compile-strip. The cost of a check is negligible compared to the cost of a missed breach.

### Sensitive-data hygiene in the message

Assertion messages reach logs. Do not log secrets, tokens, full PII, or session identifiers in the assertion text. Use opaque identifiers (`user_id=42`, not `email=...`) and a separate sensitive-data sink when truly needed.

### Pairs well with

- **Input validation** (`references/input-validation.md`) — handles the boundary; invariants protect the interior
- **Authentication patterns** (`references/authentication-patterns.md`) — session/JWT establish identity; invariants encode what that identity is allowed to touch
- **Security logging** (`references/security-logging.md`) — assertion failures should reach the security-event sink
- **Error message sanitisation** (`references/error-message-sanitization.md`) — invariant violations must not leak detail to the user
- **OWASP Top 10** (`references/owasp-top10.md`) — A01 Broken Access Control, A04 Insecure Design, A09 Logging Failures are the primary fits

## Anti-Patterns

| Anti-pattern | Why it fails |
|--------------|--------------|
| Asserting on attacker-controlled fields ("request signature is valid") | The attacker provides the field; an invariant cannot defend against its own inputs |
| Sprinkling `assert(true)` "for documentation" | Adds noise, devalues real assertions; use a comment if you want documentation |
| Wrapping the entire request in `try { ... } catch (InvariantViolation) { 200 OK }` | Defeats the point; you've built a fail-open switch with extra steps |
| Replacing input validation with assertions | Assertions are not user-facing; you lose the typed error your API contract promised |
| One giant `assert(everythingIsValid())` at the top | Granular failures are debuggable; opaque failures are not |

## Auditing for missing invariants

When reviewing a sensitive code path:

1. List the security guarantees the code is *supposed* to provide (no cross-tenant read, only owner can mutate, etc.)
2. For each guarantee, find the single line where, if you flipped it to its negation, the breach would occur
3. Ask: if that line silently misbehaved due to a future refactor, would any test catch it?
4. If no — that is where an invariant earns its keep

The audit output is a small list of "this guarantee is currently load-bearing on convention X; encode it as an assertion".
