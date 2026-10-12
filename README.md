# Dart JWK Duo

Type-safe P-256 key pairs (ES256 signing, HPKE encryption) and AES-256-GCM keys with a service-based API. All cryptography runs in [rust_jwk_duo](../rust_jwk_duo) through flutter_rust_bridge; secret key material stays in native handles. Platforms: macOS, Linux, iOS, Android (Linux and Android unverified).

## Key Types

1. **SigningKeyPair** (ECDSA P-256 / ES256) - for identity, authentication, and digital signatures
2. **EncryptionKeyPair** (P-256, JWK `alg` `HPKE-7`) - for HPKE (RFC 9180) encryption
3. **SymmetricKey** (AES-256-GCM) - for data encryption

Ciphertexts are HPKE (RFC 9180) but **not JWE**: the output is a library-specific blob
(`0x01 || encapsulated key (65) || ciphertext || tag`), not a JOSE serialization, and a JWE library cannot
open it. Only the key's `alg` name, `HPKE-7`, comes from JOSE (draft-ietf-jose-hpke-encrypt).
The shared engine and format are documented in [rust_jwk_duo](../rust_jwk_duo).

## Features

- **Type Safety**: Separate types for signing vs encryption keys prevent compile-time errors
- **RFC 7517 Compliant**: Standard JWK/JWKS format support
- **Native Crypto**: No cryptography in Dart; every call forwards to rust_jwk_duo
- **Dynamic Key IDs**: Uses RFC 7638 JWK thumbprints for collision-free key rotation
- **Service Architecture**: Clean separation between generation, validation, verification, and crypto operations

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         dart_jwk_duo                            │
├─────────────────────────────────────────────────────────────────┤
│  KeyDuo                                                         │
│  ├── SigningKeyPair (ECDSA P-256)                              │
│  │   ├── signBytes(data) → signature                           │
│  │   └── verifyBytes(signature, data) → bool                   │
│  └── EncryptionKeyPair (P-256 HPKE)                            │
│      └── HPKE (DHKEM P-256, HKDF-SHA256, AES-256-GCM)          │
│                                                                 │
│  Both pair types share one encoding surface (IKeyPair):        │
│      exportPublicKeySec1Hex()  → 130-char hex, 04||x||y        │
│      exportPublicKeyRaw()      → 65 bytes,     04||x||y        │
│      importPublicKeySec1Hex()  → public-only pair   [static]   │
│      importPublicKeyRaw()      → public-only pair   [static]   │
├─────────────────────────────────────────────────────────────────┤
│  Services                                                       │
│  ├── GenerationService - Generate new key pairs                │
│  ├── ValidationService - Structural JWK format checks          │
│  ├── VerificationService - Cryptographic roundtrip tests       │
│  │   └── verifySignatureWithPublicKeySec1Hex()                 │
│  └── CryptoService - Sign, verify, encrypt, decrypt operations │
├─────────────────────────────────────────────────────────────────┤
│  Encoding                                                       │
│  ├── HexCodec       - The one hex encoding (lowercase, fixed)  │
│  └── Sec1PublicKey  - The one public key encoding (SEC1 uncmp) │
├─────────────────────────────────────────────────────────────────┤
│  Serialization                                                  │
│  └── KeyDuoSerializer - Import/export JWK Set JSON             │
└─────────────────────────────────────────────────────────────────┘
```

## Public key encoding

This library speaks exactly **one** public key encoding, for both key types:
**SEC1 uncompressed**, `04 || x || y` — 65 bytes, 130 hex characters.

That is SEC1 §2.3.3, and identically ANSI X9.62, RFC 5480, TLS and OpenSSL. There is no second, tag-stripped "convenience"
form, because having two encodings for the same value is how a key ends up
stored in the wrong field.

Two consequences worth internalising:

- **`SigningKeyPair` and `EncryptionKeyPair` have identical encoding APIs.**
  The export members live on the `IKeyPair` interface, so neither type can
  drift ahead of the other. Choosing an encoding is never forced by which key
  type you happen to hold.
- **A signing public key and an encryption public key are indistinguishable
  by inspection.** Same length, same tag, same alphabet — and each imports
  happily as the other type, because both are just points on P-256. There is
  a test pinning this so nobody later "optimises" by trying to sniff the type.

## Telling signing and encryption apart

Since the bytes can't tell you, the type system does.

```dart
final signing    = await keyDuo.signingKeyPair.exportPublicKeySec1Hex();
final encryption = await keyDuo.encryptionKeyPair.exportPublicKeySec1Hex();
// signing    is SigningPublicKeyHex
// encryption is EncryptionPublicKeyHex

await SigningKeyPair.importPublicKeySec1Hex(encryption);  // compile error
```

`SigningPublicKeyHex` and `EncryptionPublicKeyHex` are Dart extension types:
they compile away entirely, so this costs nothing at runtime. Both implement
`String`, so every `String` member works and either can be passed where a
`String` is wanted — but never where the *other* key type is wanted.

Coming back from storage, state the purpose once, explicitly:

```dart
final key = SigningPublicKeyHex(row['signing_public_key_hex'] as String);
```

That call validates the encoding — 130 characters, `04` tag. It cannot check
that the point is on the curve, because that needs the native
library; `importPublicKeySec1Hex` does that. So holding a `SigningPublicKeyHex`
means *well-formed and declared to be a signing key*, not *verified to be a
valid point*.

For both keys at once, use `PublicKeyDuo` rather than two loose strings — its
slots are typed, so the arguments cannot be transposed, and it refuses to hold
the same key twice:

```dart
final duo = await keyDuo.exportPublicKeyDuo();
duo.toJson();  // {"signingPublicKeyHex": "...", "encryptionPublicKeyHex": "..."}
```

Across the wire, where types are gone, those field names carry the purpose.

## Usage

### Generate and Export Keys

```dart
import 'package:dart_jwk_duo/dart_jwk_duo.dart';

// Generate key pair duo
final keyDuo = await GenerationService.generateKeyDuo();

// Export as JWK Set JSON (includes private keys)
final serializer = KeyDuoSerializer();
final jwkSetJson = await serializer.exportKeyDuoJwk(keyDuo);

// Export public keys only
final publicJwkSetJson = await serializer.exportPublicKeyDuoJwk(keyDuo);
```

### Import Keys

```dart
// Import from JWK Set JSON
final serializer = KeyDuoSerializer();
final keyDuo = await serializer.importKeyDuoJwk(jwkSetJson);

// Import public-only KeyDuo
final publicKeyDuo = await serializer.importPublicKeyDuoJwk(publicJwkSetJson);
```

### Sign and Verify

```dart
// Sign data
final signature = await keyDuo.signingKeyPair.signBytes(data);

// Verify signature
final isValid = await keyDuo.signingKeyPair.verifyBytes(signature, data);

// Export public key as SEC1 hex (for auth tokens, identifiers)
final signingPublicKeyHex =
    await keyDuo.signingKeyPair.exportPublicKeySec1Hex();
// Returns 130-char hex string: '04' || x || y
```

### Verify Signature with Public Key Hex

```dart
// Import public key from SEC1 hex and verify signature
final keyPair =
    await SigningKeyPair.importPublicKeySec1Hex(signingPublicKeyHex);
final isValid = await keyPair.verifyBytes(signature, data);

// Or use the VerificationService convenience method
final isValid = await VerificationService.verifySignatureWithPublicKeySec1Hex(
  publicKeySec1Hex: signingPublicKeyHex,
  signature: signature,
  data: data,
);
```

### Encrypt to a Recipient's Public Key

Encryption is symmetric with signing: encrypting needs only the recipient's
public key, exactly as verifying needs only the signer's public key.

```dart
// Sender holds nothing but the recipient's SEC1 hex
final recipient =
    await EncryptionKeyPair.importPublicKeySec1Hex(encryptionPublicKeyHex);
final ciphertext = await CryptoService.encrypt(data, recipient);

// Only the holder of the private key can read it
final plaintext =
    await CryptoService.decrypt(ciphertext, myKeyDuo.encryptionKeyPair);
```

### Validation and Verification

```dart
// Structural validation (format checks only)
await ValidationService.validateKeyDuoJwk(jwkSetJson);

// Cryptographic verification (roundtrip tests)
final isValid = await VerificationService.verifyKeyDuo(keyDuo);

// Combined import + verification
final verifiedKeyDuo = await VerificationService.verifyKeyDuoJwk(jwkSetJson);
```

### Symmetric Key Operations

```dart
// Generate symmetric key
final symmetricKey = await GenerationService.generateSymmetricKey();

// Export as JWK
final jwk = await symmetricKey.toJwk();

// Import from JWK
final imported = await SymmetricKey.fromJwk(jwk);

// Encrypt/decrypt, optionally binding associated data
final encrypted = await CryptoService.encryptSymmetric(data, symmetricKey, aad: aad);
final decrypted = await CryptoService.decryptSymmetric(encrypted, symmetricKey, aad: aad);
```

## Security Notes

- **AES-GCM nonce limit**: Symmetric encryption uses random 96-bit IVs. Per NIST guidelines, do not exceed ~2^32 encryptions per key to keep collision probability negligible. Rotate keys before this limit.
- **Exported key strings**: Dart strings are immutable and cannot be zeroed from memory. Minimize the lifetime of strings returned by `exportKeyDuoJwk()` and `SymmetricKey.toJwk()`.

## Requirements

- Dart SDK ^3.11.0 (see `pubspec.yaml`; tested on 3.13.2) and, for apps, Flutter
- A Rust toolchain (`rustup`, stable, 1.85 or newer); `hook/build.dart` builds the engine with cargo

`await ensureInitialized()` loads the native library once; every facade method also calls it, so
calling it yourself is only needed to surface load errors early. Key objects hold native handles:
call `dispose()` on `SigningKeyPair`, `EncryptionKeyPair`, `SymmetricKey` and `KeyDuo` when done.

Until `rust_jwk_duo` is pushed and `rust/Cargo.toml` pins it by git rev, `rust/Cargo.toml` uses a path
dependency on the sibling checkout `../rust_jwk_duo`, so a consumer fetching this package from git
cannot build it. Use a checkout with both repositories side by side. At the git-rev switch, also drop the
`../rust_jwk_duo/` entry that `hook/build.dart` tracks for rebuilds.

## Migrating from 2.x

Everything not listed as removed keeps its 2.x name. "Rust" names are in the
[rust_jwk_duo README](../rust_jwk_duo/README.md#parity-table-dart_jwk_duo-200-to-rust_jwk_duo).

| 2.x | 3.0 | Rust |
|---|---|---|
| `JwkAlgorithm.ecdhEs256` (`ECDH-ES+A256KW`) | removed: replaced by `JwkAlgorithm.hpke7` (`HPKE-7`) | `jwk_algorithm::HPKE7` |
| `CryptoSizes.hkdfSaltLength`, `hybridHeaderLength` | removed: the old recipe had a salt and IV header; HPKE has neither | none |
| `DefaultKeyIds`, `KeyIdFormatting` | removed: no callers | none |
| `IKeyPair<T>` (generic), `.privateKey`, `.publicKey` | `IKeyPair` (not generic, + `dispose()`); the WebCrypto getters are removed: no WebCrypto | `KeyPair` trait |
| `IKeyDuo` | unchanged | `KeyDuo` (no trait) |
| `SigningKeyPair(...)`, `.publicOnly(...)`, `EncryptionKeyPair(...)`, `.publicOnly(...)` | removed: constructors took WebCrypto keys. Use `GenerationService`, `KeyDuoSerializer`, `importPublicKeySec1Hex` or `importPublicKeyRaw` | `generate`, `import_public_key_*` |
| `SigningKeyPair.importPublicKeySec1Hex/Raw`, `signBytes`, `verifyBytes`, `export*`, `calculateKeyId` | unchanged | `import_public_key_*`, `sign_bytes`, `verify_bytes`, `KeyPair` trait |
| `EncryptionKeyPair.importPublicKeySec1Hex/Raw`, `export*` | unchanged | same |
| `KeyDuo(signing:, encryption:)` | no longer `const`; throws `ArgumentError` if both halves share a public key | `KeyDuo::new` |
| `KeyDuo.encrypt/decrypt/encryptString/decryptString` | unchanged, plus named `info`, `aad` | `encrypt(data, info, aad)` ... |
| `KeyDuo.sign/verifySignature/signString/verifySignatureString`, `exportPublicKeyDuo` | unchanged | `sign`, `verify_signature`, ... |
| `SymmetricKey.fromJwk/toJwk` | unchanged; 256-bit keys only; + `dispose()` | `SymmetricKey::from_jwk/to_jwk` |
| `SymmetricKey.fromAesKey`, `.internal` | removed: WebCrypto types | none |
| `ExportedJwk(...)` constructor | removed: build one by exporting a key; `toJson`, `toPublicOnly`, `keyId`, `alg`, `use` stay | `ExportedJwk` |
| `CryptoService.encrypt/decrypt/encryptString/decryptString` | unchanged, plus named `info`, `aad` | `CryptoService::encrypt/decrypt/...` |
| `CryptoService.encryptSymmetric/decryptSymmetric` | unchanged, plus named `aad` | `encrypt_symmetric/decrypt_symmetric` |
| `CryptoService.sign/verifySignature/signString/verifySignatureString` | unchanged | same |
| `GenerationService.*` | unchanged | `GenerationService::*` |
| `ValidationService.*` | unchanged names; every method except `extractPublicKeyFields` is now a `Future` (await it) | `ValidationService::*` |
| `VerificationService.*` | unchanged | `VerificationService::*` |
| `KeyDuoSerializer.export*/import*/extract*` | unchanged; 2.x JWK Sets are rejected | `KeyDuoSerializer::*` |
| `KeyDuoSerializer.verifyJwk` | removed: duplicate of `VerificationService.verifyKeyDuoJwk` | removed |
| `calculateJwkThumbprint`, `HexCodec`, `Sec1PublicKey`, `*PublicKeyHex`, `PublicKeyDuo` | unchanged | same names in snake_case |

## Native build and toolchain setup

The crypto lives in `rust/` (bridge crate over `../rust_jwk_duo`); `hook/build.dart` builds it with
cargo for macOS, Linux, iOS and Android. Toolchain setup:

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk        # Android only; also set ANDROID_NDK_HOME
cargo install flutter_rust_bridge_codegen --version 2.11.1 --locked
```

Regenerate the bridge with `flutter_rust_bridge_codegen generate` (`lib/src/bridge/` is generated;
`analysis_options.yaml` excludes it, which must stay in place or codegen's formatter rewrites it into
code that does not compile). `rust/Cargo.lock` pins `libc` to 0.2.180: 0.2.190 breaks the
`backtrace` crate on iOS targets.

Tests: `dart test` runs the whole suite, including `test/conformance_test.dart`, which reads the shared
vectors from the sibling repo (`JWK_DUO_CONFORMANCE_DIR`, default `../rust_jwk_duo/conformance`). Some of
those vectors are frozen Rust outputs rather than independent known-answer tests; see
`../rust_jwk_duo/conformance/README.md`.

### Linux

**Not verified.** Docker was unavailable when this was written, so the command below has never been run.
It mounts the parent directory (both repos as siblings under `/src`), so the container writes `rust/target`
into the mounted repo (gitignored). Run it from the `dart_jwk_duo` directory:

```bash
docker run --rm -v "$PWD/..:/src" -w /src/dart_jwk_duo dart:3.11 bash -c 'apt-get update && apt-get install -y curl build-essential && curl -sSf https://sh.rustup.rs | sh -s -- -y && . $HOME/.cargo/env && dart pub get && dart test'
```

### Platform loading

`ensureInitialized()` (`lib/src/init.dart`) picks the library as follows: the `DART_JWK_DUO_NATIVE_LIB`
environment variable if set (a path to the library); on macOS and Linux, the hook's output under
`rust/target/native-assets/` or `.dart_tool/`; on iOS and Android, `JwkDuoRust.init()` with no argument
(flutter_rust_bridge's default loading).

- **macOS: tested** (`dart test`).
- **iOS: verified on the simulator only.** A throwaway Flutter app depending on this package by path called
  `ensureInitialized()`, `generateKeyDuo()` and `formatVersion()` from `main()`. Built with
  `flutter build ios --simulator` (Flutter 3.47.2, Xcode 26.3; needs the rustup targets
  `aarch64-apple-ios-sim` and `x86_64-apple-ios`, since Flutter builds both simulator archs), installed
  with `xcrun simctl install` and launched with `xcrun simctl launch` on the iPhone 17 Pro simulator. The library
  was bundled as `Runner.app/Frameworks/dart_jwk_duo_bridge.framework/dart_jwk_duo_bridge` and the no-argument
  `init()` found it. Not tested on a physical device or on the `aarch64-apple-ios` (iPhoneOS) target.
- **Android: UNVERIFIED, not run.** The dev machine has no Android toolchain (no adb, emulator,
  cargo-ndk or NDK). The Android branch of `hook/build.dart` has never executed, and whether
  `JwkDuoRust.init()` finds `libdart_jwk_duo_bridge.so` is unknown.
- **Linux: UNVERIFIED, not run** (see above).

### Conformance on mobile (`example/conformance_app`)

A Flutter app whose `integration_test` runs the same 11 vector files as `test/conformance_test.dart`
through `runConformance`, loading them from the asset bundle, and asserts the same per-file and total
counts (a truncated asset set fails). Run `example/conformance_app/tool/copy_conformance.sh` first: it copies
the vectors from `../rust_jwk_duo/conformance` (or `JWK_DUO_CONFORMANCE_DIR`) into the gitignored
`assets/conformance/` and exits non-zero if the source is missing or too few files were copied. Then
`cd example/conformance_app && flutter test integration_test -d <device id>`.

- **iOS simulator: passed, re-verified 2026-10-12 after the HPKE string bridge functions were added** (iPhone 17 Pro, Flutter 3.47.2, Xcode 26.3): 384 cases ran and passed, 8 were
  skipped (`exported_jwk.check`, Rust-only), zero failures.
- **Android emulator: NOT RUN** (no Android toolchain on the dev machine).

## License

MIT License
