# SSH Forced-Command Wrappers: Allowlist Bypass via Argument Injection

A common way to give an automated client (CI, a backup job, a monitoring probe) narrow
access to a host is an SSH **forced command**: the public key in `authorized_keys` is
prefixed with `restrict,command="/usr/local/bin/<wrapper> <arg>"`, so *any* login with
that key runs the wrapper instead of an interactive shell. The wrapper is supposed to be
the security boundary — it decides which of the client's requests are allowed through.

The client's requested command arrives in `$SSH_ORIGINAL_COMMAND`. A wrapper that
**validates that string and then re-executes it** is almost always bypassable. This is
argument injection ([CWE-88](https://cwe.mitre.org/data/definitions/88.html)), adjacent
to OS command injection ([CWE-78](https://cwe.mitre.org/data/definitions/78.html), see
[`cwe-top25.md`](cwe-top25.md) Rank 9). The same failure appears in `sudo` NOPASSWD
wrappers, `git-shell` replacements, and `rsync --server` wrappers — anywhere an allowlist
inspects a string that an interpreter later re-parses.

## 1. The construction flaw: validate once, parse twice

The defect is not a weak regex — it is the architecture. The wrapper treats the client's
command as a **string to approve**, then hands that same string to a shell:

```sh
CMD="$SSH_ORIGINAL_COMMAND"
# ... some validation of "$CMD" ...
exec sh -c "$CMD"      # <-- the string is parsed a SECOND time, by the shell
```

The check and the execution parse the bytes under **different rules**. To the validator a
quoted region is just characters in a flat string; to the shell it is a single argument
whose quotes are stripped. So a payload can satisfy every check as a *substring* while the
shell delivers it as *real, separate arguments* to the target program.

## 2. A broken wrapper (generalized)

Assume the wrapper is meant to allow exactly two `mysqldump` invocations against one fixed
`${CONTAINER}` and reject everything else. Its validation has two stages:

**Stage A — a metacharacter denylist** (substring scan on the raw string):

```sh
case "$CMD" in
  *";"*|*"|"*|*"&"*|*'$('*|*'`'*|*">"*|*"<"*|*"
"*) echo "denied: metacharacter" >&2; exit 1 ;;
esac
```

**Stage B — a glob allowlist** requiring a known command shape to appear *somewhere*:

```sh
case "$CMD" in
  "docker exec -e MYSQL_PWD="*" ${CONTAINER} mysqldump --no-data --routines --events"*"-u"*) : ;;
  "docker exec -e MYSQL_PWD="*" ${CONTAINER} mysqldump --routines --events"*"-u"*)          : ;;
  *) echo "denied: not on allowlist" >&2; exit 1 ;;
esac
exec sh -c "$CMD"
```

The `*` right after `MYSQL_PWD=` is the hole: a glob `*` matches **any** text, including
spaces and quotes. The allowlist only requires its literal fragments to occur in order —
it says nothing about what fills the wildcard.

## 3. The bypass

Smuggle the real payload inside the quoted value of `-e MYSQL_PWD=…`. Because it is a
single quoted shell word, it contains **no metacharacters** the denylist looks for, yet it
carries the allowlisted fragments so the glob still matches:

```sh
docker exec -e MYSQL_PWD="X <container> mysqldump --no-data --routines --events \
  --single-transaction --quick --no-tablespaces -u" -u 0 <container> rm -rf /var/lib/mysql
```

- Stage A passes: no `;`, `|`, `&`, `$(`, backtick, `>`, `<`, or newline anywhere.
- Stage B passes: the required literal fragments all appear inside the `MYSQL_PWD` value.

## 4. What actually runs

Validation "saw" one long string. After `exec sh -c "$CMD"` the shell strips the quotes and
hands `docker` these arguments:

```text
argv[0] = docker
argv[1] = exec
argv[2] = -e
argv[3] = MYSQL_PWD=X <container> mysqldump --no-data --routines --events --single-transaction --quick --no-tablespaces -u
argv[4] = -u      argv[5] = 0      argv[6] = <container>
argv[7] = rm      argv[8] = -rf    argv[9] = /var/lib/mysql
```

This is `docker`'s own argument vector, not shell positional parameters: under
`exec sh -c "$CMD"` the `$n` would belong to the shell, whose `$0` names the shell
invocation rather than `docker`.

The dump fragments are inert — they sit inside the value of `argv[3]`. The operative arguments
are `-u 0 <container> rm -rf /var/lib/mysql`: run `rm -rf` as uid 0 inside the target
container, **with no database credential required**. Any command runs this way; data
destruction is only one example.

## 5. The rule: build the command, never validate a foreign one

A forced-command wrapper must **not** approve and re-run a client-supplied command string.
It must construct the command from its own hard-wired values and accept from the client
only a minimal, strictly validated vocabulary:

```sh
# The client sends ONLY a keyword from a fixed set (+ optional narrow parameter).
ACTION="$SSH_ORIGINAL_COMMAND"
case "$ACTION" in
  dump-schema) set -- mysqldump --no-data --routines --events --single-transaction \
                       --quick --no-tablespaces "$DB" ;;
  dump-full)   set -- mysqldump --routines --events --single-transaction \
                       --quick "$DB" ;;
  *) echo "denied" >&2; exit 1 ;;
esac
exec docker exec -e MYSQL_PWD="$(cat /root/.dbpass)" "$CONTAINER" "$@"   # exec directly — no `sh -c`
```

Principles:

- **Execute as an argument vector** (`exec docker … "$@"`), never `sh -c "$string"`. No
  second parse means nothing to inject into.
- **Fixed values live in the wrapper**, not in the request: container name, flags,
  and the target binary are constants the client cannot influence.
- **Accept a closed vocabulary.** A keyword from a known set; if a list must be passed,
  validate it whole, e.g. `printf %s "$ARG" | grep -qE '^[A-Za-z0-9_]+(,[A-Za-z0-9_]+)*$'`.
- **Keep value-bearing parameters out of the command.** Passwords and paths belong in a
  root-only file or the environment (`MYSQL_PWD` from `/root/.dbpass`), not in a string the
  client helped build.
- A denylist of metacharacters is not a substitute for any of the above — this bypass uses
  none.

## 6. Why this generalizes

The same validate-then-reparse pattern recurs wherever an allowlist guards a string that a
downstream interpreter splits again:

- **`sudo` NOPASSWD wrappers** that forward `"$@"` (or `$*`) into another command.
- **`git-shell` replacement scripts** that parse the requested git command from a string.
- **`rsync --server` wrappers** that inspect the incoming argument line before running it.
- Any "command proxy" that pattern-matches input and then calls `eval`, `sh -c`, `bash -c`,
  or `system()` on it.

Classify as CWE-88 (argument injection); the executed effect is CWE-78 (OS command
injection). See [`input-validation.md`](input-validation.md) for the allowlist-over-denylist
principle these share.

## 7. How to test a wrapper (the transferable part)

Prove both directions in a sandbox — never against production, and never with a real
destructive payload on a live target.

1. **Show what validation accepts.** Copy the wrapper and replace the final executing line
   (`exec sh -c …` / `exec docker …`) with `echo`. Feeding candidates through this copy
   shows which strings pass the checks, executing nothing.
2. **Show what would actually run.** Put a stub named after the target binary (e.g.
   `docker`) first on `PATH`; have it print its arguments, one per line. Now the difference
   between "what was validated" and "what the program receives" — including quote stripping
   — is visible.
   ```sh
   #!/bin/sh
   i=0; for a in "$@"; do printf '$%d=[%s]\n' "$i" "$a"; i=$((i+1)); done
   ```
3. **Optional — test the sshd integration, not just the script.** Run a throwaway `sshd` in
   a container with the real forced command in `authorized_keys`, then drive it over a real
   SSH connection. This catches how sshd itself hands `$SSH_ORIGINAL_COMMAND` to the wrapper.

A test table must assert **both** that legitimate calls pass **and** that bypasses are
rejected — a suite that only confirms the happy path would have marked the broken wrapper
above as correct.

| Input command                                   | Validation | Actually executes         | Expected |
|-------------------------------------------------|------------|---------------------------|----------|
| allowed `mysqldump` (schema)                    | pass       | the intended dump         | pass     |
| allowed `mysqldump` (full)                      | pass       | the intended dump         | pass     |
| `whoami`                                         | reject     | —                         | reject   |
| bare `mysqldump …` (no `docker exec` wrapper)   | reject     | —                         | reject   |
| dump against a different container              | reject     | —                         | reject   |
| anything containing `;` or `\|`                  | reject     | —                         | reject   |
| `-e MYSQL_PWD="… -u" -u 0 <container> rm -rf …` | **reject** | arbitrary cmd as uid 0    | reject   |

The broken wrapper passes the last row and executes it; a wrapper built per §5 rejects it
because the client can send only a keyword, and there is no second parse to inject into.

## When to apply

- Auditing any key in `authorized_keys` carrying a `command="…"` (forced command).
- Reviewing `sudo` NOPASSWD entries, `git-shell` / `rsync` wrappers, or any "command proxy"
  script that matches input and then calls `eval` / `sh -c` / `system()`.
- Whenever remote or reduced-privilege access is enforced by a script that **inspects** a
  supplied command instead of **constructing** one from a fixed vocabulary.
