# Documentation audit

## Contract synchronized in this pass

The README, roadmap, Release 2 plan, architecture, SELinux status document, and
manual pages were aligned to the implemented contract at `d269526`:

- Release 2 is local; remote transport, non-loopback listening, and TLS are
  deferred;
- both native package formats carry user- and system-mode deployment assets;
- tarball system installation is an explicit operator action;
- operator client endpoint/token selection is automatic by default with
  explicit overrides retained;
- credential installation, default credential name, init root defaults, Bash
  completion, and the active AppArmor/SELinux backend contract are documented;
- SELinux container labeling is no longer described as `label=disable`;
- the missing README code fence in principal provisioning is closed;
- `completion` and SELinux behavior are included in the manual pages;
- the SELinux research document now distinguishes implemented behavior,
  completed openSUSE evidence, and outstanding release acceptance.

## Remaining release decisions that documentation cannot settle

### `/opt` under SELinux

Application policy permits `/opt`, but the policy currently grants workspace
access only to `user_home_type`. User-facing documentation can state the
application rule, but must not claim that arbitrary `/opt` labels work under
SELinux until UAT proves a safe policy or init rejects the root. Resolve the
implementation contract, then update all root-policy examples together.

### RPM distribution support

The roadmap cannot claim Fedora/RHEL support while the RPM hard-depends on
`apparmor-parser`. Select and test the Release 2 RPM target, or change the
package architecture, before publishing a compatibility matrix.

### CA compatibility range

Documentation correctly describes an OpenSSL-compatible SHA-1 subject-name
hash. The exact supported OpenSSL compatibility range needs a conformance
matrix before it can be stated more narrowly. The source-path contract also
remains a release decision: current configuration accepts an absolute path,
while system MAC policy cannot promise arbitrary readable locations.

## Documentation ownership recommendation

- README: installation, first use, supported modes, and security summary.
- `docs/architecture.md`: binding trust, capability, lifecycle, and
  logging/event contracts.
- `docs/release-2-plan.md`: current release scope, completion state, and gates;
  no obsolete implementation diary.
- `docs/selinux-support-plan.md`: SELinux decision record, policy contract,
  evidence, and outstanding UAT.
- man pages: exact installed CLI/config reference.
- audit directory: dated findings; do not copy detailed audit notes into the
  living contract documents.
