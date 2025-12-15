/// Core interfaces for type-safe key pair management.
library;

import 'package:webcrypto/webcrypto.dart';
import 'exported_jwk.dart';

/// Generic interface for a cryptographic key pair.
/// 
/// Provides type-safe access to private and public keys, along with
/// export functionality that returns structured DTOs with guaranteed metadata.
/// 
/// [TPrivate] - The type of the private key (e.g., RsaPssPrivateKey)
/// [TPublic] - The type of the public key (e.g., RsaPssPublicKey)
abstract class IKeyPair<TPrivate, TPublic> {
  /// The private key of this key pair, or null if this is a public-only key pair
  TPrivate? get privateKey;
  
  /// The public key of this key pair
  TPublic get publicKey;
  
  /// Whether this key pair has a private key available
  bool get hasPrivateKey;
  
  /// Exports the private key as an ExportedJwk DTO.
  /// 
  /// Returns an ExportedJwk containing the private key with all RSA components
  /// (including private exponent 'd') and proper metadata (kid, alg, use).
  /// 
  /// Throws [StateError] if this is a public-only key pair.
  Future<ExportedJwk> exportPrivateKey();
  
  /// Exports the public key as an ExportedJwk DTO.
  /// 
  /// Returns an ExportedJwk containing only public key components
  /// (no private exponent 'd') with proper metadata (kid, alg, use).
  Future<ExportedJwk> exportPublicKey();
  
  /// Calculates the RFC 7638 JWK thumbprint for this key pair.
  /// 
  /// Returns a base64url-encoded SHA-256 hash of the canonical public key.
  Future<String> calculateKeyId();
  
  /// Validates that the private and public keys are mathematically paired.
  /// 
  /// Performs a cryptographic test to ensure the keys belong to the same
  /// RSA key pair. This is an expensive operation that should only be used
  /// when key pair integrity is uncertain.
  /// 
  /// Returns `true` if keys are properly paired, `false` otherwise.
  /// Throws [StateError] if this is a public-only key pair.
  Future<bool> validateKeyPair();
}

/// Interface for a container holding both signing and encryption key pairs.
/// 
/// Provides type-safe access to both key pairs with compile-time guarantees
/// about the key types and their intended uses.
abstract class IKeyDuo {
  /// The signing key pair (RSA-PSS-256)
  /// 
  /// Used for digital signatures and authentication.
  IKeyPair<RsaPssPrivateKey?, RsaPssPublicKey> get signing;
  
  /// The encryption key pair (RSA-OAEP-256)
  /// 
  /// Used for data encryption and protection.
  IKeyPair<RsaOaepPrivateKey?, RsaOaepPublicKey> get encryption;
}