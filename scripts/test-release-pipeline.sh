#!/usr/bin/env bash
#
# test-release-pipeline.sh — deterministic tests for the release candidate
# producer / promotion-verify / artifact-resolver helper scripts.
#
# The tests run the REAL scripts (scripts/release-candidate.sh,
# scripts/release-promote-verify.sh, scripts/release-candidate-artifact.sh)
# against a scratch repo tree with MOCK authoritative builders and MOCK
# dpkg-deb/rpm tool shims, so the producer/verification logic is exercised
# without a full build toolchain (no go/musl-gcc/nfpm needed).
#
# Provenance invariants proven here:
#   * candidate set contains exactly one tarball/DEB/RPM;
#   * SHA256SUMS is producer-owned, generated once, and verified;
#   * candidate.manifest binds source SHA + version + checksums;
#   * candidate SHA mismatch is fatal;
#   * source-SHA metadata mismatch is fatal;
#   * version/tag mismatch is fatal;
#   * promotion does not invoke build scripts and never regenerates SHA256SUMS;
#   * consumers resolve exactly one artifact of the requested type from the
#     producer SHA256SUMS.
#
# Usage: scripts/test-release-pipeline.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0

ok()   { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1" >&2; }

# expect_fail runs a command that must exit non-zero and match a pattern.
expect_fail() {
  local desc="$1" pattern="$2"; shift 2
  local out ec
  out="$("$@" 2>&1)"
  ec=$?
  if [ "$ec" -eq 0 ]; then
    bad "$desc (expected failure, but exited 0)"
    return
  fi
  if [ -n "$pattern" ] && ! printf '%s' "$out" | grep -qF "$pattern"; then
    bad "$desc (failure did not mention '$pattern'; output: $out)"
    return
  fi
  ok "$desc"
}

# --- Scaffold a scratch repo tree ---------------------------------------------

make_repo() {
  local repo="$1"
  mkdir -p "$repo/scripts" "$repo/dist"
  cp "$SRC_DIR/scripts/release-candidate.sh" "$repo/scripts/release-candidate.sh"
  cp "$SRC_DIR/scripts/release-promote-verify.sh" "$repo/scripts/release-promote-verify.sh"
  cp "$SRC_DIR/scripts/release-candidate-artifact.sh" "$repo/scripts/release-candidate-artifact.sh"

  # Mock authoritative builders (same names/contract as the real ones).
  cat > "$repo/build-bundle.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
VERSION="${1:?}"
D="$(cd "$(dirname "$0")" && pwd)/dist"
mkdir -p "$D"
  printf '#!/usr/bin/env bash\necho "%s"\n' "${FAKE_BIN_VERSION:-$VERSION}" > "$D/docker-helper"
  chmod +x "$D/docker-helper"
  printf 'bundle-content\n' > "$D/bundle-content.txt"
  tar czf "$D/docker-helper-${VERSION}-linux-amd64.tar.gz" \
    --owner=0 --group=0 --numeric-owner -C "$D" bundle-content.txt
EOF
  cat > "$repo/build-packages.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
VERSION="${1:?}"
D="$(cd "$(dirname "$0")" && pwd)/dist"
mkdir -p "$D"
printf '#!/usr/bin/env bash\necho "%s"\n' "${FAKE_BIN_VERSION:-$VERSION}" > "$D/docker-helper"
chmod +x "$D/docker-helper"
printf 'fake-deb-%s\n' "$VERSION" > "$D/docker-helper_${VERSION}_amd64.deb"
printf 'fake-rpm-%s\n' "$VERSION" > "$D/docker-helper-${VERSION}-1.x86_64.rpm"
EOF
  chmod +x "$repo/build-bundle.sh" "$repo/build-packages.sh"

  # Mock package-identity tools (same CLI contract the producer uses).
  mkdir -p "$repo/shims"
  cat > "$repo/shims/dpkg-deb" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "--info" ]; then
  printf 'Package: docker-helper\nArchitecture: amd64\n'
  exit 0
fi
if [ "$1" = "--contents" ]; then
  printf '%s\n' \
    './usr/bin/docker-helper' \
    './usr/lib/systemd/system/docker-helper.service' \
    './etc/apparmor.d/docker-helper-system' \
    './usr/share/man/man1/docker-helper.1.gz' \
    './usr/share/man/man5/docker-helper-config.5.gz' \
    './usr/share/doc/docker-helper/LICENSE'
  exit 0
fi
exit 1
EOF
  cat > "$repo/shims/rpm" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "-qp" ]; then
  case "${3:-}" in
    '%{NAME}')   printf 'docker-helper\n' ;;
    '%{ARCH}')   printf 'x86_64\n' ;;
    '%{LICENSE}') printf 'GPL-3.0-only\n' ;;
    *) exit 1 ;;
  esac
  exit 0
fi
if [ "$1" = "-qpl" ]; then
  printf '%s\n' \
    '/usr/bin/docker-helper' \
    '/usr/lib/systemd/system/docker-helper.service' \
    '/etc/apparmor.d/docker-helper-system' \
    '/usr/share/man/man1/docker-helper.1.gz' \
    '/usr/share/man/man5/docker-helper-config.5.gz' \
    '/usr/share/doc/docker-helper/LICENSE'
  exit 0
fi
exit 1
EOF
  chmod +x "$repo/shims/dpkg-deb" "$repo/shims/rpm"
}

VERSION="2.1.0-uat"
SOURCE_SHA="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

REPO="$WORK/repo"
make_repo "$REPO"
PATH="$REPO/shims:$PATH"  # mock dpkg-deb/rpm
export PATH

run_producer() {
  ( cd "$REPO" && scripts/release-candidate.sh "$VERSION" "$SOURCE_SHA" )
}

# --- T1: happy-path producer ---------------------------------------------------
if run_producer > "$WORK/producer.log" 2>&1; then
  ok "producer stages a candidate set"
else
  bad "producer failed on the happy path (see $WORK/producer.log)"
  cat "$WORK/producer.log" >&2
fi

CAND="$REPO/dist/candidate"

# Candidate set contains exactly one tarball/DEB/RPM plus SHA256SUMS + manifest.
count_of() {
  ls "$CAND"/*"$1" 2>/dev/null | wc -l
}
[ "$(count_of .tar.gz)" = "1" ] && ok "candidate set contains exactly one tarball" \
  || bad "candidate set must contain exactly one tarball"
[ "$(count_of .deb)" = "1" ] && ok "candidate set contains exactly one DEB" \
  || bad "candidate set must contain exactly one DEB"
[ "$(count_of .rpm)" = "1" ] && ok "candidate set contains exactly one RPM" \
  || bad "candidate set must contain exactly one RPM"
[ -f "$CAND/SHA256SUMS" ] && ok "candidate set contains producer SHA256SUMS" \
  || bad "candidate set missing SHA256SUMS"
[ -f "$CAND/candidate.manifest" ] && ok "candidate set contains candidate.manifest" \
  || bad "candidate set missing candidate.manifest"

# SHA256SUMS covers exactly the three artifacts and matches on-disk hashes.
sha_lines="$(grep -vc '^[[:space:]]*$' "$CAND/SHA256SUMS" || true)"
[ "$sha_lines" = "3" ] && ok "SHA256SUMS contains exactly 3 entries" \
  || bad "SHA256SUMS must contain exactly 3 entries (found $sha_lines)"
( cd "$CAND" && sha256sum --check SHA256SUMS ) >/dev/null 2>&1 \
  && ok "SHA256SUMS verifies the staged artifacts" \
  || bad "SHA256SUMS does not verify the staged artifacts"

# Manifest binds source SHA, version and the producer checksums.
grep -q "^source_sha=$SOURCE_SHA$" "$CAND/candidate.manifest" \
  && ok "candidate.manifest binds source SHA" \
  || bad "candidate.manifest missing/bad source_sha"
grep -q "^version=$VERSION$" "$CAND/candidate.manifest" \
  && ok "candidate.manifest binds version" \
  || bad "candidate.manifest missing/bad version"
for key in tarball deb rpm; do
  name="$(sed -n "s/^$key=\([^ ]*\).*/\1/p" "$CAND/candidate.manifest")"
  msha="$(sed -n "s/^$key=[^ ]* //p" "$CAND/candidate.manifest")"
  rsha="$(awk -v f="$name" '$2==f {print $1}' "$CAND/SHA256SUMS")"
  [ "$msha" = "$rsha" ] && [ -n "$rsha" ] \
    && ok "candidate.manifest $key checksum matches SHA256SUMS" \
    || bad "candidate.manifest $key checksum does not match SHA256SUMS"
done

# --- T2: exactly-one tarball invariant -----------------------------------------
REPO2="$WORK/repo-two-tars"
make_repo "$REPO2"
cat > "$REPO2/build-bundle.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
VERSION="${1:?}"
D="$(cd "$(dirname "$0")" && pwd)/dist"
mkdir -p "$D"
printf '#!/usr/bin/env bash\necho "%s"\n' "$VERSION" > "$D/docker-helper"
chmod +x "$D/docker-helper"
printf 'a\n' > "$D/bundle-a.txt"
printf 'b\n' > "$D/bundle-b.txt"
tar czf "$D/docker-helper-${VERSION}-linux-amd64.tar.gz" \
  --owner=0 --group=0 --numeric-owner -C "$D" bundle-a.txt
tar czf "$D/docker-helper-${VERSION}-linux-amd64.extra.tar.gz" \
  --owner=0 --group=0 --numeric-owner -C "$D" bundle-b.txt
EOF
chmod +x "$REPO2/build-bundle.sh"
( cd "$REPO2" && scripts/release-candidate.sh "$VERSION" "$SOURCE_SHA" ) >/dev/null 2>&1
if [ $? -ne 0 ]; then
  ok "producer rejects a dist with two tarballs (exactly-one invariant)"
else
  bad "producer must fail when dist contains more than one tarball"
fi

# --- T3: binary version mismatch is fatal ---------------------------------------
REPO3="$WORK/repo-wrong-version"
make_repo "$REPO3"
( cd "$REPO3" && FAKE_BIN_VERSION="wrong-version" scripts/release-candidate.sh "$VERSION" "$SOURCE_SHA" ) >/dev/null 2>&1
if [ $? -ne 0 ]; then
  ok "producer rejects a binary version mismatch"
else
  bad "producer must fail when the built binary version mismatches VERSION"
fi

# --- T-own: non-root archive ownership is fatal ----------------------------------
# Regression: build-bundle.sh used to record the builder's UID/GID in the
# tarball. A mock builder that reproduces that leak (explicit non-root numeric
# ownership, as a root-less runner produces) must fail closed in the producer.
REPO_OWN="$WORK/repo-bad-ownership"
make_repo "$REPO_OWN"
cat > "$REPO_OWN/build-bundle.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
VERSION="${1:?}"
D="$(cd "$(dirname "$0")" && pwd)/dist"
mkdir -p "$D"
printf '#!/usr/bin/env bash\necho "%s"\n' "$VERSION" > "$D/docker-helper"
chmod +x "$D/docker-helper"
printf 'bundle-content\n' > "$D/bundle-content.txt"
tar czf "$D/docker-helper-${VERSION}-linux-amd64.tar.gz" \
  --owner=12345 --group=12345 --numeric-owner -C "$D" bundle-content.txt
EOF
chmod +x "$REPO_OWN/build-bundle.sh"
expect_fail "producer rejects a tarball with non-root archive ownership" "not owned 0:0" \
  bash -c "cd '$REPO_OWN' && scripts/release-candidate.sh '$VERSION' '$SOURCE_SHA'"

# --- T4: promotion verification happy path + producer SHA256SUMS reused ----------
SHA_BEFORE="$(sha256sum "$CAND/SHA256SUMS" | awk '{print $1}')"
MANIFEST_BEFORE="$(sha256sum "$CAND/candidate.manifest" | awk '{print $1}')"
if scripts/release-promote-verify.sh "$CAND" "$VERSION" "$SOURCE_SHA" "v$VERSION" > "$WORK/promote.log" 2>&1; then
  ok "promote-verify accepts the staged candidate for tag v$VERSION"
else
  bad "promote-verify rejected a valid candidate (see $WORK/promote.log)"
  cat "$WORK/promote.log" >&2
fi
SHA_AFTER="$(sha256sum "$CAND/SHA256SUMS" | awk '{print $1}')"
MANIFEST_AFTER="$(sha256sum "$CAND/candidate.manifest" | awk '{print $1}')"
[ "$SHA_BEFORE" = "$SHA_AFTER" ] && ok "promote-verify does not regenerate SHA256SUMS (producer file reused)" \
  || bad "promote-verify modified SHA256SUMS (it must reuse the producer file)"
[ "$MANIFEST_BEFORE" = "$MANIFEST_AFTER" ] && ok "promote-verify does not modify candidate.manifest" \
  || bad "promote-verify modified candidate.manifest"

# --- T5: candidate SHA mismatch is fatal -----------------------------------------
CAND2="$WORK/cand-corrupt"
cp -r "$CAND" "$CAND2"
printf 'tampered\n' >> "$CAND2"/docker-helper-*.tar.gz
expect_fail "candidate SHA mismatch is fatal" "FAILED" \
  scripts/release-promote-verify.sh "$CAND2" "$VERSION" "$SOURCE_SHA" "v$VERSION"

# --- T6: source-SHA metadata mismatch is fatal -----------------------------------
expect_fail "source-SHA metadata mismatch is fatal" "source SHA mismatch" \
  scripts/release-promote-verify.sh "$CAND" "$VERSION" "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" "v$VERSION"

# --- T7: version / tag mismatch is fatal -----------------------------------------
expect_fail "candidate version mismatch is fatal" "version mismatch" \
  scripts/release-promote-verify.sh "$CAND" "9.9.9" "$SOURCE_SHA" "v$VERSION"
expect_fail "tag version mismatch is fatal" "tag version mismatch" \
  scripts/release-promote-verify.sh "$CAND" "$VERSION" "$SOURCE_SHA" "v9.9.9"

# --- T8: promotion does not invoke build scripts / regenerated content -------------
for bad_ref in build-bundle.sh build-packages.sh build-static.sh nfpm completion 'go build'; do
  if grep -qF "$bad_ref" "$SRC_DIR/scripts/release-promote-verify.sh"; then
    bad "release-promote-verify.sh must not reference $bad_ref"
  else
    ok "release-promote-verify.sh does not reference $bad_ref"
  fi
done
if grep -qE '>[[:space:]]*SHA256SUMS' "$SRC_DIR/scripts/release-promote-verify.sh"; then
  bad "release-promote-verify.sh must never write SHA256SUMS"
else
  ok "release-promote-verify.sh never writes SHA256SUMS (producer-owned)"
fi

# --- T10+: promotion verification set identity + manifest contract --------------
# Every negative test mutates a COPY of the canonical candidate set so the
# original stays intact. Helper: digest recorded in a candidate's SHA256SUMS.

sha_of() { awk -v f="$2" '$2==f {print $1}' "$1/SHA256SUMS"; }

# A. The exact review exploit: SHA256SUMS lists the tarball three times and
# DEB/RPM have no checksum entries. The old verifier only counted 3 lines and
# accepted this; the hardened verifier must reject it.
CAND_A="$WORK/cand-tar-x3"
cp -r "$CAND" "$CAND_A"
TAR_NAME="$(basename "$CAND_A"/*.tar.gz)"
TAR_SHA="$(sha_of "$CAND_A" "$TAR_NAME")"
printf '%s  %s\n%s  %s\n%s  %s\n' "$TAR_SHA" "$TAR_NAME" "$TAR_SHA" "$TAR_NAME" "$TAR_SHA" "$TAR_NAME" > "$CAND_A/SHA256SUMS"
expect_fail "review exploit: SHA256SUMS with tarball three times is fatal" "duplicate checksum entries" \
  scripts/release-promote-verify.sh "$CAND_A" "$VERSION" "$SOURCE_SHA" "v$VERSION"

# B. SHA256SUMS has tarball + DEB + an unrelated filename; RPM is missing. The
# missing artifact's manifest key is dropped too, mirroring the review exploit:
# an attacker controls both SHA256SUMS and candidate.manifest, so the old
# verifier accepted this (the DEB/RPM bytes would go unpublished-unverified)
# while the hardened verifier must reject it.
CAND_B="$WORK/cand-unrelated"
cp -r "$CAND" "$CAND_B"
TAR_NAME="$(basename "$CAND_B"/*.tar.gz)"
TAR_SHA="$(sha_of "$CAND_B" "$TAR_NAME")"
DEB_NAME="$(basename "$CAND_B"/*.deb)"
DEB_SHA="$(sha_of "$CAND_B" "$DEB_NAME")"
printf 'fake-unrelated\n' > "$CAND_B/unrelated.bin"
EVIL_SHA="$(sha256sum "$CAND_B/unrelated.bin" | awk '{print $1}')"
printf '%s  %s\n%s  %s\n%s  %s\n' "$TAR_SHA" "$TAR_NAME" "$DEB_SHA" "$DEB_NAME" "$EVIL_SHA" "unrelated.bin" > "$CAND_B/SHA256SUMS"
grep -Ev '^rpm=' "$CAND_B/candidate.manifest" > "$CAND_B/manifest.tmp"
mv "$CAND_B/manifest.tmp" "$CAND_B/candidate.manifest"
expect_fail "SHA256SUMS with an unrelated filename (RPM missing) is fatal" "no checksum entry" \
  scripts/release-promote-verify.sh "$CAND_B" "$VERSION" "$SOURCE_SHA" "v$VERSION"

# C. Duplicate checksum entry for one expected artifact.
CAND_C="$WORK/cand-dup-sha"
cp -r "$CAND" "$CAND_C"
TAR_NAME="$(basename "$CAND_C"/*.tar.gz)"
TAR_SHA="$(sha_of "$CAND_C" "$TAR_NAME")"
DEB_NAME="$(basename "$CAND_C"/*.deb)"
DEB_SHA="$(sha_of "$CAND_C" "$DEB_NAME")"
RPM_NAME="$(basename "$CAND_C"/*.rpm)"
RPM_SHA="$(sha_of "$CAND_C" "$RPM_NAME")"
printf '%s  %s\n%s  %s\n%s  %s\n%s  %s\n' "$TAR_SHA" "$TAR_NAME" "$TAR_SHA" "$TAR_NAME" \
  "$DEB_SHA" "$DEB_NAME" "$RPM_SHA" "$RPM_NAME" > "$CAND_C/SHA256SUMS"
expect_fail "duplicate SHA256SUMS entry for one artifact is fatal" "must contain exactly 3 entries" \
  scripts/release-promote-verify.sh "$CAND_C" "$VERSION" "$SOURCE_SHA" "v$VERSION"

# D. Manifest missing tarball=, deb= or rpm= is fatal (one case per artifact key).
for miss in tarball deb rpm; do
  CAND_D="$WORK/cand-manifest-missing-$miss"
  cp -r "$CAND" "$CAND_D"
  grep -v "^${miss}=" "$CAND_D/candidate.manifest" > "$CAND_D/manifest.tmp"
  mv "$CAND_D/manifest.tmp" "$CAND_D/candidate.manifest"
  expect_fail "candidate.manifest missing $miss= is fatal" "is missing $miss" \
    scripts/release-promote-verify.sh "$CAND_D" "$VERSION" "$SOURCE_SHA" "v$VERSION"
done

# E. Manifest artifact filename does not match the actual artifact.
CAND_E="$WORK/cand-manifest-wrong-name"
cp -r "$CAND" "$CAND_E"
sed -i 's/^tarball=[^ ]*/tarball=other.tar.gz/' "$CAND_E/candidate.manifest"
expect_fail "manifest tarball filename mismatch is fatal" "!= actual artifact" \
  scripts/release-promote-verify.sh "$CAND_E" "$VERSION" "$SOURCE_SHA" "v$VERSION"

# F. Manifest artifact checksum does not match SHA256SUMS.
CAND_F="$WORK/cand-manifest-bad-sha"
cp -r "$CAND" "$CAND_F"
sed -i 's/^deb=\([^ ]*\) [0-9a-f]\{64\}/deb=\1 0000000000000000000000000000000000000000000000000000000000000000/' "$CAND_F/candidate.manifest"
expect_fail "manifest checksum mismatch is fatal" "checksum" \
  scripts/release-promote-verify.sh "$CAND_F" "$VERSION" "$SOURCE_SHA" "v$VERSION"

# G. Duplicate manifest artifact key is fatal.
CAND_G="$WORK/cand-manifest-dup"
cp -r "$CAND" "$CAND_G"
cp "$CAND_G/candidate.manifest" "$CAND_G/manifest.tmp"
grep '^rpm=' "$CAND_G/candidate.manifest" >> "$CAND_G/manifest.tmp"
mv "$CAND_G/manifest.tmp" "$CAND_G/candidate.manifest"
expect_fail "duplicate manifest artifact key is fatal" "duplicate rpm" \
  scripts/release-promote-verify.sh "$CAND_G" "$VERSION" "$SOURCE_SHA" "v$VERSION"

# H. SHA256SUMS filename containing a directory/path-traversal path is fatal
# (covers path traversal and absolute / directory-qualified names).
for badname in "../../evil" "/etc/passwd" "subdir/artifact"; do
  CAND_H="$WORK/cand-bad-path-$RANDOM"
  cp -r "$CAND" "$CAND_H"
  TAR_NAME="$(basename "$CAND_H"/*.tar.gz)"
  TAR_SHA="$(sha_of "$CAND_H" "$TAR_NAME")"
  DEB_NAME="$(basename "$CAND_H"/*.deb)"
  DEB_SHA="$(sha_of "$CAND_H" "$DEB_NAME")"
  RPM_NAME="$(basename "$CAND_H"/*.rpm)"
  RPM_SHA="$(sha_of "$CAND_H" "$RPM_NAME")"
  printf '%s  %s\n%s  %s\n%s  %s\n' "$TAR_SHA" "$badname" "$DEB_SHA" "$DEB_NAME" "$RPM_SHA" "$RPM_NAME" > "$CAND_H/SHA256SUMS"
  expect_fail "SHA256SUMS path '$badname' is fatal" "invalid artifact path" \
    scripts/release-promote-verify.sh "$CAND_H" "$VERSION" "$SOURCE_SHA" "v$VERSION"
done

# Manifest unrecognized keys are fatal: the producer contract is exactly the
# five keys above, so an unrelated metadata line must never be tolerated.
CAND_UK="$WORK/cand-manifest-unknown"
cp -r "$CAND" "$CAND_UK"
printf 'unrelated=something\n' >> "$CAND_UK/candidate.manifest"
expect_fail "manifest unrecognized key is fatal" "unrecognized entry" \
  scripts/release-promote-verify.sh "$CAND_UK" "$VERSION" "$SOURCE_SHA" "v$VERSION"

# --- T9: artifact resolver ----------------------------------------------------------
for type in deb rpm tar; do
  resolved="$(scripts/release-candidate-artifact.sh "$CAND" "$type")"
  if [ -n "$resolved" ]; then
    set -- $resolved
    rpath="$1"; rsha="$2"
    [ -f "$rpath" ] && [ -n "$rsha" ] \
      && ok "artifact resolver resolves $type from producer SHA256SUMS" \
      || bad "artifact resolver returned invalid $type entry: $resolved"
  else
    bad "artifact resolver failed for $type"
  fi
done
expect_fail "artifact resolver rejects an unknown type" "unknown artifact type" \
  scripts/release-candidate-artifact.sh "$CAND" "exe"
expect_fail "artifact resolver rejects a missing candidate dir" "does not exist" \
  scripts/release-candidate-artifact.sh "$WORK/does-not-exist" "deb"
CAND3="$WORK/cand-nosums"
cp -r "$CAND" "$CAND3"
rm "$CAND3/SHA256SUMS"
expect_fail "artifact resolver rejects a candidate set without SHA256SUMS" "SHA256SUMS missing" \
  scripts/release-candidate-artifact.sh "$CAND3" "deb"

# --- Summary -----------------------------------------------------------------------
echo
echo "=================== test-release-pipeline summary ==================="
echo "passed: $PASS  failed: $FAIL"
echo "====================================================================="
[ "$FAIL" -eq 0 ]
