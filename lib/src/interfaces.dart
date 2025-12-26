/// Core interfaces for type-safe key pair management.
library;

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
  
  /// Calculates the RFC 7638 JWK thumbprint for this key pair.
  /// 
  /// Returns a base64url-encoded SHA-256 hash of the canonical public key.
  Future<String> calculateKeyId();
  
  /// Validates that the private and public keys are mathematically paired.
  /// 
  /// Performs a cryptographic roundtrip test to prove the keys work together.
  /// Returns `true` if keys are properly paired, `false` otherwise.
  /// Throws [StateError] if this is a public-only key pair.
  Future<bool> verifyKeyPair();
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
  
  /// The encryption key pair (RSA-OAEP-256)
  /// 
  /// Used for data encryption and protection.
  IKeyPair<RsaOaepPrivateKey?, RsaOaepPublicKey> get encryption;
}