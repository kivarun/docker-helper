# Layering, parallel implementations, and dead code

## Release findings

### Dead principal runtime cleanup

`cleanupPrincipalRuntimeDirs` in `principal.go` has no production caller. Its
only caller is a dedicated test. The principal-delete handler already obtains
the deleted session IDs transactionally and performs best-effort runtime cleanup
itself.

Delete the unused function and its orphan test. Do not preserve or repair its
direct global `slog.Warn` call; the live handler is the authoritative cleanup
path and uses request-scoped logging.

### Duplicated system-init preflight

The AppArmor and SELinux init paths repeat backend-neutral state checks and
transaction ordering. This is an active parallel implementation, not merely
similar code. Consolidate it as described in `01-high-level-abstractions.md`.

### Completion duplicates configuration vocabulary

`configFields` is the configuration authority, while `completion.go`, CLI help,
the manuals, and README repeat writable/unsettable field lists. At minimum,
completion should derive field names from the registry. A declarative metadata
model for value completion can follow after Release 2.

### SELinux policy copies an upstream semantic template

`docker_helper_container_t` is assigned `container_domain` and
`mcs_constrained_type`, then the policy manually reproduces the permissions
needed by container-selinux's container file-management template. This is a
parallel implementation across a package boundary: it can compile while
silently diverging from the installed container-selinux version.

For Release 2, accept it only after live compatibility tests on every claimed
RPM target. For the next release, build against supported refpolicy interfaces,
generate the module from an explicit compatibility layer, or narrow the support
matrix.

## Smaller cleanup items

- `attrDER.raw` in the CA subject canonicalizer is stored but never read.
- The CA attribute sorter is a hand-written sort with no domain-specific
  behavior; use the standard library when the subsystem is next changed.
- `session.go` compatibility paths and operation shutdown/cancel variants were
  inspected and still express distinct supported semantics; they are not dead
  code and should not be collapsed for style.

## Recommendation

Before 2.0, remove only confirmed dead code and fix the release blockers. Keep
the broader consolidation work for the next release unless it is needed to make
a blocker fix safe. This limits late structural churn while recording clear
ownership boundaries.
