# Indistinguishability Defences (Decoys, Dummy Responses, Constant-Time Paths)

When an endpoint must not reveal whether a subject exists — a username, an
account, a tenant, a licence key — the usual defence is to answer the unknown
case with something that *looks like* the known case: dummy credentials, a decoy
record, a synthetic delay. The defence only works if an observer cannot
distinguish the two. Getting that wrong is subtle, and the failure is silent:
the code looks defensive, the tests pass, and the oracle is still open.

Three rules, each of which has been violated in a shipped fix.

## 1. Never derive a published value from material that also selected its shape

If the response's observable properties (length, count, flags, transports) are
chosen from bytes that are *themselves published*, the observer can recompute the
selection and check it.

```php
// VULNERABLE: $material[0] picks the length, and $material's head IS the id
$material    = hash_hmac('sha256', $subject . '|' . $i, $key, true);
$length      = LENGTHS[ord($material[0]) % count(LENGTHS)];
$transports  = SETS[ord($material[1]) % count(SETS)];
$id          = substr($material, 0, $length);   // publishes bytes 0 and 1
```

An unauthenticated caller now tests `strlen($id) === LENGTHS[ord($id[0]) % n]`
and `$transports === SETS[ord($id[1]) % m]`. Both hold for **every** decoy and
for a genuine record only by coincidence — and never when the real value's shape
falls outside the hardcoded sets. The test is one-sided, so **any response that
fails it is certainly real**. One request classifies the subject.

```php
// FIXED: independent derivations under distinct labels
$selectors = hash_hmac('sha256', $subject . '|' . $i . '|selectors', $key, true);
$id        = deriveId($key, $subject . '|' . $i . '|id', $length);
```

Note the constants being private buys nothing: in open-source or any shipped
client they are readable, and the attacker only needs the relation.

## 2. Never stretch a published value by hashing its own published prefix

The same defect one level down, and it appears precisely when fixing rule 1 —
the output must be longer than one hash block, so the obvious stretch is to
append a hash of what you already have:

```php
// VULNERABLE: the head is published, so the tail is computable from it
$id = $material;
while (strlen($id) < $length) {
    $id .= hash('sha256', $material . '|' . ++$block, true);
}
// attacker: substr($id, 32) === hash('sha256', substr($id, 0, 32) . '|1', true)
```

Every long decoy satisfies that; no real value does. Derive **every block** from
the key instead, so no published byte predicts another:

```php
while (strlen($id) < $length) {
    $id .= hash_hmac('sha256', $label . '|' . $block++, $key, true);
}
```

## 3. Verify from the response alone, against the unfixed code first

A test for this class must compute **only from what the endpoint returns** — that
is the attacker's position. Two failure modes to avoid:

- **Restating the constants in the test.** A hardcoded copy stops matching the
  implementation the moment either changes, and the test then passes vacuously.
  Read them from the implementation (reflection, an exported test hook), which is
  also the faithful attacker model since they are public.
- **Trusting a green result.** Run the test against the **unfixed** code and
  watch it fail before you keep it. A test written after the fix, never run
  against the defect, proves nothing about the defect.

Report the measurement, not the intent: *"47 of 47 decoys satisfied the
attacker's relation before, none beyond chance after"* is a result;
*"decoys are now indistinguishable"* is a claim.

## Related shapes

The same reasoning applies beyond decoy records:

| Defence | The tell to check |
|---|---|
| Dummy password verification for unknown users | Is the fake hash the same cost/algorithm as a real one? |
| Constant-time comparison | Does an early length check leak before the comparison runs? |
| Padded response timing | Is the pad applied to **both** branches, to a fixed budget — not added to one? |
| Generic error messages | Do status code, body length, and headers match across branches? |
| Decoy record counts | Can the count be zero for one branch only? An empty list no unknown subject can produce is itself the oracle. |

The unifying question: *enumerate everything the observer receives — bytes,
count, timing, status, headers — and ask which of them the branch decided.*
