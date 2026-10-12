/// Core interfaces for type-safe key pair management.
library;

import 'dart:typed_data';
import 'exported_jwk.dart';

/// Generic interface for a cryptographic key pair.
///
/// Secret material stays inside the native library; this interface only
/// exposes exports that return structured DTOs with guaranteed metadata.
abstract class IKeyPair {
  /// Whether this key pair has a private key available
  bool get hasPrivateKey;

  /// Exports the private key as an ExportedJwk DTO.
  ///
  /// Throws [StateError] if this is a public-only key pair.
  Future<ExportedJwk> exportPrivateKey();

  /// Exports the public key as an ExportedJwk DTO.
  Future<ExportedJwk> exportPublicKey();

  /// Exports the public key as SEC1 uncompressed bytes.
  ///
  /// Always exactly 65 bytes: the `04` tag followed by the 32-byte x and
  /// 32-byte y coordinates.
  Future<Uint8List> exportPublicKeyRaw();

  /// Exports the public key as SEC1 uncompressed hex.
  ///
  /// Always exactly 130 lowercase hex characters beginning `04`, being the
  /// hex of [exportPublicKeyRaw].
  ///
  /// The bytes carry no indication of whether this key is for signing or for
  /// key agreement — a signing public key and an encryption public key of the
  /// same curve are indistinguishable by inspection. Callers must carry
  /// purpose in field names and types, never infer it from the value.
  Future<String> exportPublicKeySec1Hex();

  /// Calculates the RFC 7638 JWK thumbprint for this key pair.
  ///
  /// Returns a base64url-encoded SHA-256 hash of the canonical public key.
  Future<String> calculateKeyId();

  /// Releases the native key handle. The key pair must not be used afterwards.
  void dispose();
}

/// Interface for a container holding both signing and encryption key pairs.
abstract class IKeyDuo {
  /// The signing key pair (ECDSA P-256)
  IKeyPair get signing;

  /// The encryption key pair (HPKE, P-256)
  IKeyPair get encryption;
}
