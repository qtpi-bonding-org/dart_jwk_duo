# JWK Duo

A thin, type-safe wrapper around `package:webcrypto` for managing a JWK Set containing exactly 2 RSA key pairs:

1. **Signing Key** (RSA-PSS-256) - for identity/authentication  
2. **Encryption Key** (RSA-OAEP-256) - for data protection

## Features

- **Type Safety**: Separate types for signing vs encryption keys prevent compile-time errors
- **RFC 7517 Compliant**: Standard JWK/JWKS format support
- **Minimal Abstraction**: Ultra-thin wrapper over webcrypto
- **Dynamic Key IDs**: Uses RFC 7638 JWK thumbprints for collision-free key rotation

## Usage

```dart
import 'package:jwk_duo/jwk_duo.dart';

// Generate key pair duo
final generator = KeyDuoGenerator();
final keyDuo = await generator.generateKeyDuo();

// Export as JWK Set
final serializer = KeyDuoSerializer();
final jwkSetJson = await serializer.exportKeyDuo(keyDuo);

// Import from JWK Set
final importedKeyDuo = await serializer.importKeyDuo(jwkSetJson);
```

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