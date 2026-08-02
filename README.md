# Dart JWK Duo

A thin, type-safe wrapper around `package:webcrypto` for managing cryptographic key pairs with clean service-based architecture.

## Key Types

1. **SigningKeyPair** (ECDSA P-256 / ES256) - for identity, authentication, and digital signatures
2. **EncryptionKeyPair** (ECDH P-256) - for key agreement and hybrid encryption
3. **SymmetricKey** (AES-256-GCM) - for data encryption

## Features

- **Type Safety**: Separate types for signing vs encryption keys prevent compile-time errors
- **RFC 7517 Compliant**: Standard JWK/JWKS format support
- **Web Compatible**: Uses ECDH P-256 for encryption (works in browsers)
- **Minimal Abstraction**: Ultra-thin wrapper over webcrypto
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
│  └── EncryptionKeyPair (ECDH P-256)                            │
│      └── ECDH key agreement + AES-GCM hybrid encryption        │
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

That is SEC1 §2.3.3, and identically ANSI X9.62, RFC 5480, TLS, OpenSSL and
WebCrypto's `"raw"` format. There is no second, tag-stripped "convenience"
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
that the point is on the curve, because that needs an async `webcrypto`
import; `importPublicKeySec1Hex` does that. So holding a `SigningPublicKeyHex`
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
ValidationService.validateKeyDuoJwk(jwkSetJson);

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
final jwk = await symmetricKey.exportJwk();

// Import from JWK
final imported = await SymmetricKey.importJwk(jwkMap);

// Encrypt/decrypt (use with CryptoService or directly)
final encrypted = await symmetricKey.internal.encryptBytes(data, iv);
final decrypted = await symmetricKey.internal.decryptBytes(encrypted, iv);
```

## Security Notes

- **AES-GCM nonce limit**: Symmetric encryption uses random 96-bit IVs. Per NIST guidelines, do not exceed ~2^32 encryptions per key to keep collision probability negligible. Rotate keys before this limit.
- **Exported key strings**: Dart strings are immutable and cannot be zeroed from memory. Minimize the lifetime of strings returned by `exportKeyDuoJwk()` and `SymmetricKey.toJwk()`.

## Requirements

- Flutter SDK >=3.0.0
- Dart SDK >=3.0.0

## Setup

This package depends on `package:webcrypto` which requires native library setup:

```bash
flutter pub get
flutter pub run webcrypto:setup
```

## License

MIT License
