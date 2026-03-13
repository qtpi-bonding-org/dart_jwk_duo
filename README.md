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
│  │   ├── verifyBytes(signature, data) → bool                   │
│  │   ├── exportPublicKeyHex() → 128-char hex                   │
│  │   └── importPublicKeyHex(hex) → SigningKeyPair (public-only)│
│  └── EncryptionKeyPair (ECDH P-256)                            │
│      └── Used for ECDH key agreement + AES-GCM encryption      │
├─────────────────────────────────────────────────────────────────┤
│  Services                                                       │
│  ├── GenerationService - Generate new key pairs                │
│  ├── ValidationService - Structural JWK format checks          │
│  ├── VerificationService - Cryptographic roundtrip tests       │
│  │   └── verifySignatureWithPublicKeyHex() - Verify with hex   │
│  └── CryptoService - Sign, verify, encrypt, decrypt operations │
├─────────────────────────────────────────────────────────────────┤
│  Serialization                                                  │
│  └── KeyDuoSerializer - Import/export JWK Set JSON             │
└─────────────────────────────────────────────────────────────────┘
```

## Usage

### Generate and Export Keys

```dart
import 'package:dart_jwk_duo/dart_jwk_duo.dart';

// Generate key pair duo
final keyDuo = await GenerationService.generateKeyDuo();

// Export as JWK Set JSON (includes private keys)
final serializer = KeyDuoSerializer();
final jwkSetJson = await serializer.exportKeyDuo(keyDuo);

// Export public keys only
final publicJwkSetJson = await serializer.exportPublicKeyDuo(keyDuo);
```

### Import Keys

```dart
// Import from JWK Set JSON
final serializer = KeyDuoSerializer();
final keyDuo = await serializer.importKeyDuo(jwkSetJson);

// Import public-only KeyDuo
final publicKeyDuo = await serializer.importPublicKeyDuo(publicJwkSetJson);
```

### Sign and Verify

```dart
// Sign data
final signature = await keyDuo.signingKeyPair.signBytes(data);

// Verify signature
final isValid = await keyDuo.signingKeyPair.verifyBytes(signature, data);

// Export public key as hex (for auth tokens, identifiers)
final publicKeyHex = await keyDuo.signingKeyPair.exportPublicKeyHex();
// Returns 128-char hex string (64 bytes = x + y coordinates)
```

### Verify Signature with Public Key Hex

```dart
// Import public key from hex and verify signature
final keyPair = await SigningKeyPair.importPublicKeyHex(publicKeyHex);
final isValid = await keyPair.verifyBytes(signature, data);

// Or use VerificationService convenience method
final isValid = await VerificationService.verifySignatureWithPublicKeyHex(
  publicKeyHex: publicKeyHex,
  signature: signature,
  data: data,
);
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
- **Exported key strings**: Dart strings are immutable and cannot be zeroed from memory. Minimize the lifetime of strings returned by `exportKeyDuo()` and `SymmetricKey.toJwk()`.

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
