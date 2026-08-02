/// Core interfaces for type-safe key pair management.
library;

import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';
import 'exported_jwk.dart';

/// Generic interface for a cryptographic key pair.
/// 
/// Provides type-safe access to private and public keys, along with
/// export functionality that returns structured DTOs with guaranteed metadata.
/// 
/// [TPrivate] - The type of the private key (e.g., EcdsaPrivateKey)
/// [TPublic] - The type of the public key (e.g., EcdsaPublicKey)
abstract class IKeyPair<TPrivate, TPublic> {
  /// The private key of this key pair, or null if this is a public-only key pair
  TPrivate? get privateKey;
  
  /// The public key of this key pair
  TPublic get publicKey;
  
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
  /// 32-byte y coordinates. Equivalent to WebCrypto's `"raw"` format.
  ///
  /// Declared here rather than on the concrete types so that every key pair
  /// is guaranteed to offer the same encoding surface. A key pair type that
  /// only speaks JWK forces its callers onto a different encoding from
  /// everyone else, which is exactly how signing and encryption keys end up
  /// stored in each other's fields.
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
}

/// Interface for a container holding both signing and encryption key pairs.
/// 
/// Provides type-safe access to both key pairs with compile-time guarantees
/// about the key types and their intended uses.
abstract class IKeyDuo {
  /// The signing key pair (ECDSA P-256)
  /// 
  /// Used for digital signatures and authentication.
  IKeyPair<EcdsaPrivateKey?, EcdsaPublicKey> get signing;
  
  /// The encryption key pair (ECDH P-256)
  /// 
  /// Used for key agreement and hybrid encryption.
  IKeyPair<EcdhPrivateKey?, EcdhPublicKey> get encryption;
}