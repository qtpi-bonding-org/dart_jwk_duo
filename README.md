# Dart JWK Duo

Type-safe P-256 key pairs (ES256 signing, HPKE encryption) and AES-256-GCM keys with a service-based API. All cryptography runs in [rust_jwk_duo](../rust_jwk_duo) through flutter_rust_bridge; secret key material stays in native handles. Platforms: macOS, Linux, iOS, Android.

## Key Types

1. **SigningKeyPair** (ECDSA P-256 / ES256) - for identity, authentication, and digital signatures
2. **EncryptionKeyPair** (P-256, JWK `alg` `HPKE-7`) - for HPKE (RFC 9180) encryption
3. **SymmetricKey** (AES-256-GCM) - for data encryption

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

- Flutter SDK >=3.0.0
- Dart SDK >=3.0.0

## Setup

The native library is built by `hook/build.dart` (see "3.0 native build" below).
Call `await ensureInitialized()` once, or let any facade method do it for you.

## License

MIT License

## 3.0 native build (flutter_rust_bridge over rust_jwk_duo)

The crypto lives in `rust/` (bridge crate over `../rust_jwk_duo`); `hook/build.dart` builds it with cargo
for macOS, Linux, iOS and Android. Toolchain setup:

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
vectors from the sibling repo (`JWK_DUO_CONFORMANCE_DIR`, default `../rust_jwk_duo/conformance`). Linux,
with both repos mounted as siblings under `/src`:

```bash
docker run --rm -v /Users/aicoder/Documents/my-libs:/src -w /src/dart_jwk_duo dart:3.11 bash -c 'apt-get update && apt-get install -y curl build-essential && curl -sSf https://sh.rustup.rs | sh -s -- -y && . $HOME/.cargo/env && dart pub get && dart test'
```

`dart test test/bridge_smoke_test.dart` on Dart 3.11 needs no extra flag for build hooks
(native assets are enabled by default); the loader finds the hook's output under `rust/target/native-assets/`
or override with `DART_JWK_DUO_NATIVE_LIB`.

### Platform loading

`ensureInitialized()` (`lib/src/init.dart`) calls `JwkDuoRust.init()` with no argument on mobile.

- **iOS: verified (simulator only).** A throwaway Flutter app depending on this package by path called
  `ensureInitialized()`, `generateKeyDuo()` and `formatVersion()` from `main()`. Built with
  `flutter build ios --simulator` (Flutter 3.47.2, Xcode 26.3; needs the rustup targets
  `aarch64-apple-ios-sim` and `x86_64-apple-ios`, since Flutter builds both simulator archs), installed
  with `xcrun simctl install` on the iPhone 17 Pro simulator, launched with `xcrun simctl launch`. Log
  output: `flutter: SPIKE OK formatVersion=1 parts=RDuoParts`. The library was bundled as
  `Runner.app/Frameworks/dart_jwk_duo_bridge.framework/dart_jwk_duo_bridge` and the no-argument
  `init()` found it. No change to the hook or to `ensureInitialized()` was needed. Not tested on a
  physical device or on the `aarch64-apple-ios` (iPhoneOS) target.
- **Android: UNVERIFIED, not run.** The dev machine has no Android toolchain (no adb, emulator,
  cargo-ndk or NDK). The Android branch of `hook/build.dart` exists per Task 18 but has never executed,
  and whether `JwkDuoRust.init()` finds `libdart_jwk_duo_bridge.so` is unknown.
