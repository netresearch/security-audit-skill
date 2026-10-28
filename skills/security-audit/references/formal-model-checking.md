<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: Netresearch DTT GmbH -->

# Formal Model Checking for Security Guarantees

Use a small state model when a concrete security claim depends on ordering,
concurrent actors, persistence or failures. Ordinary input checks and routine
bug fixes do not require a model. A counterexample can be the complete result
of a design review; it does not create an implementation or CI assignment.

## Contents

- [Define the claim and its boundary](#define-the-claim-and-its-boundary)
- [Preserve the failure boundaries](#preserve-the-failure-boundaries)
- [Check the checker](#check-the-checker)
- [Map the model to implementation](#map-the-model-to-implementation)
- [Keep runtime evidence separate](#keep-runtime-evidence-separate)

## Define the claim and its boundary

Write the exact property, initial state, actor/value bounds and environmental
assumptions. Record the model revision, checker version, configuration and
completion result. Distinguish safety from liveness: a bounded check of "no
unaudited committed mutation" does not prove eventual delivery or termination.
For external proof claims, inspect the actual theorem and trusted assumptions;
behavior agreement or error freedom need not imply that execution terminates.

Example: "Every committed local secret version has its matching durable audit
entry." Keep historical mutations observable: a newer audited value can hide
an older unaudited commit if the property checks only the latest record.
Identify the local adapter and operations covered; do not silently extend the
claim to custom adapters, hooks, read counters or unrelated writers.

## Preserve the failure boundaries

Separate pending data from committed data. Model competing requests when their
ordering matters, and permit process loss at each relevant persistence step.
A crash runs no `catch` or `finally`. Bundling mutation and audit into one
atomic model action is justified only by a matching implementation boundary.

For example, `commit mutation -> process loss -> audit never written` disproves
the example claim. Restoring a captured snapshot after another writer commits
can additionally overwrite that writer's change. A service postcondition
observes neither failure reliably and cannot roll back an earlier commit.

Use the simplest suitable formalism; TLA+/TLC is one option, not a dependency
for every security assessment. Do not impose a global lock, coordinator or
outbox before the requested guarantee and real storage semantics justify it.

## Check the checker

To support a positive bounded-model claim, collect the evidence below. A genuine
counterexample instead supports a negative result and may complete the design
review; producing a repaired passing model is a separate assignment.

| Evidence | Acceptance criterion |
| --- | --- |
| Intended model | The complete configured reachable-state search finishes with the intended property holding |
| Known unsafe protocol | The intended invariant is violated and the checker supplies an interpretable counterexample |
| Reachability | Successful operations and important crash/failure/concurrent paths are possible; constraints do not remove the disputed behavior |

A parser error, timeout, unrelated invariant failure or missing result does
not pass a negative control. Parsing, exit zero or a partial success log alone
does not establish a complete search. Check reachability explicitly: a model
where no operation commits can satisfy audit completeness vacuously. Review
the specification itself as well as the green tool result.

## Map the model to implementation

When implementation exists, map each action to its actual operation. For
database operations, examine the relevant connection identities, transaction
owner, savepoint/isolation behavior and lock lifetime. Include relationship
tables and anchors if the claim includes them. Releasing a nested savepoint is
not the outer commit. A lock released before that commit may allow another
writer to observe an old audit tip. For a design without code, state which
implementation obligations remain unverified.

Synchronous listeners can participate through the same transactional database
connection. Their external files, remote calls or independently committed
connections do not share that commit. A durable delivery obligation would need
its own recovery/liveness contract. Validate secondary interactions rather than copying one repair:
rolled-back MySQL inserts can consume IDs, but changing allocation to avoid
false alarms must preserve the existing tamper-detection contract.

## Keep runtime evidence separate

For a design-only request, return the model result, mapping, assumptions and
unverified implementation questions. Do not edit application behavior or CI.
If implementation or runtime verification is requested, turn useful
counterexamples into regression tests on the actual database and schema.
Confirm a failing baseline or deliberately unsafe variant before claiming a fix.

For process loss, start a separate worker, confirm an observable checkpoint
before the disputed audit/commit boundary, then verify the injected termination
and durable state independently. A bootstrap failure or an exception that runs
cleanup is not equivalent evidence. Use barriers and bounded waits for
concurrent tests; mocked `begin`/`commit` calls do not prove database behavior.

Report separately the bounded model result, executed implementation tests,
revision/environment, assumptions, excluded paths and incomplete checks.
Tests connecting model actions to code are not a formal refinement or
equivalence proof. Within an implementation assignment, retain a rerunnable
check and model-to-code mapping; change CI only within the authorized scope.

## Primary sources

- [Lamport: safety, liveness and vacuous implication](https://lamport.azurewebsites.net/tla/tutorial/session9.html)
- [Doctrine DBAL 4.3: transaction nesting and savepoints](https://www.doctrine-project.org/projects/doctrine-dbal/en/4.3/reference/transactions.html)
- [SQLite: atomic commit and its assumptions](https://www.sqlite.org/atomiccommit.html)
- [MySQL 8.4: auto-increment allocation and rollback gaps](https://dev.mysql.com/doc/refman/8.4/en/innodb-auto-increment-handling.html)

Verify these semantics against the application's actual platform and version.
