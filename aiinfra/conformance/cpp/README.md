# Independent C++20 CCSE-v1 conformance consumer

This directory contains a clean consumer of the shared CCSE-v1 JSON vectors.
It does not call the Go implementation and it does not copy the expected byte
strings into C++ source. The executable strictly parses fixture inputs,
reconstructs the payload, domain, envelope and complete preimage, then compares
each derived result with the fixture's expected values.

## Pinned/tested dependencies

- Language: ISO C++20, no compiler extensions. The reproducible evidence path
  requires Linux x86-64 with GCC/G++ `15.2.0`; it rejects a different compiler
  before downloading or building dependencies.
- Cryptography: OpenSSL `3.5.5`. The evidence path checks the CLI before build
  and checks both the header and loaded `libcrypto` versions reported by the
  executable. SHA-256, Ed25519 seed-to-public-key derivation, signing and
  verification all use OpenSSL EVP. There is no local cryptographic
  implementation.
- JSON: no external dependency. Internal `strict-json revision 1` implements
  the RFC 8259 grammar in `src/strict_json.hpp` as a conformance-only, bounded
  parser (2 MiB input, 1 MiB strings, 100,000 values, depth 32). It rejects
  duplicate keys, trailing data, invalid UTF-8/escapes and unknown fields at
  every fixture schema level. Its self-tests run before the vectors.
- NFC: ICU `72.1`, whose normalization data is Unicode `15.0.0`. The source is
  pinned in `toolchain.lock` to the release URL and SHA-256
  `a2d2d38217092a7ed56635e34467f92f976b370e20182ad325edea6681a71d68`.
  The executable checks both `u_getVersion` and `u_getUnicodeVersion` through
  the ICU C ABI. ICU development headers are not required by the consumer.

`toolchain.lock` is an intentionally strict WS0.1a lock, not a version range.
The scripts reject missing, duplicate, unknown or changed entries.

## Build and run

For a fail-closed conformance run, use an absolute, untracked workspace
directory. The provisioner downloads into a quarantine filename, verifies the
archive on every run, and only then lists and extracts it. A mismatched archive
is never extracted or reused.

```sh
scripts/reproducible-test.sh \
  --work-dir /absolute/path/to/.codex-tmp/cpp-ccse \
  --jobs 8
```

The command builds ICU and the consumer outside this source directory, then
runs the shared positive and negative vectors with:

```text
CPH_CCSE_ICU_LIBRARY=/absolute/path/to/libicuuc.so.72.1
CPH_CCSE_ICU_ABI=72
```

It exits `0` only after verifying GCC/G++ 15.2.0, OpenSSL 3.5.5, explicit ICU
72.1, Unicode 15.0.0, all vectors, and the absence of a `PROVISIONAL` result.
Once the verified archive is cached, `--offline` forbids network access and
fails if that archive is missing or its digest differs.

The equivalent Make entry point is:

```sh
make test-reproducible \
  WORK_DIR=/absolute/path/to/.codex-tmp/cpp-ccse \
  JOBS=8
```

For an ordinary local build:

```sh
make
make test-provider-selection
make test-provisional
```

`test-provider-selection` verifies that an unset, partial, conflicting or
unloadable explicit selection returns dependency-blocker status `2` without
falling back to an ambient library.

`test-provisional` explicitly opts into ambient ICU discovery. It expects the
consumer's dependency-blocker exit status `2`, while still executing the
vectors. Ambient discovery can never produce a conformance PASS, even if it
happens to find Unicode 15 tables. This prevents host-library ambiguity from
becoming evidence.

Or build with CMake (the version lock is optional for development builds):

```sh
cmake -S . -B build-cmake \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCPH_CCSE_ENFORCE_LOCKED_TOOLCHAIN=ON
cmake --build build-cmake --parallel
```

Exit status is `0` only for complete conformance, `1` for a failed vector or
parser/crypto invariant, `2` for a dependency blocker, and `64` for invalid CLI
usage.

## Provider-selection contract

The default is fail-closed: with no provider environment variables, no ICU is
loaded. Explicit selection requires both `CPH_CCSE_ICU_LIBRARY` (an absolute
path) and `CPH_CCSE_ICU_ABI` (the decimal ABI suffix). Failure to load that exact
file, a missing suffixed symbol, the wrong ICU or Unicode version, or a partial
environment configuration returns dependency-blocker status `2`; there is no
fallback to another installed library.

Development-only discovery requires
`CPH_CCSE_ALLOW_AMBIENT_ICU=1`. It cannot be combined with explicit selection,
and values other than exactly `1` are rejected. The current host's ambient
`libicuuc.so.78` reports ICU `78.2.0` / Unicode `17.0.0`; vectors can run with
it, but every result is labelled `PROVISIONAL` and the process exits `2`.

Downloaded archives, extracted source, installed libraries, build outputs and
evidence logs belong under the caller-supplied work directory. They must not be
added to Git or placed below this `cpp/` source directory.

## Covered contract

The consumer covers fixed-width big-endian integers, length-framed byte/string
values (including fixed-width values), explicit optional presence, canonical
set ordering and duplicate rejection, extension sorting/framing, SHA-256 over
the full preimage, and Ed25519 over that digest. It executes all required shared
negative cases, including expectation binding, expiry, exact extension
registration, revocation, duplicate/idempotent replay, rollback-safe retry,
sequence replay across key rotation, scoped message-ID conflict and algorithm
downgrade. Audience expectations use exact canonical-set equality. Replay keys
are typed tuples matching the Go scope (`counter kind`, replay domain, sender,
environment, chain and genesis); signature key IDs are intentionally excluded.

Message type `100` is conformance-only and registers no signed extensions.
Accordingly, both critical and non-critical unknown signed extensions are
rejected; transport-only fields outside the signed projection are out of scope.
