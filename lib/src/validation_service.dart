/// Service for structural JWK validation (format checks).
library;

import 'dart:convert';
import 'constants.dart';

/// Service for structural JWK validation (format checks only)
/// 
/// Validates JWK structure and required fields without performing
/// cryptographic operations. Use VerificationService for crypto roundtrip tests.
class ValidationService {
  /// Validate KeyDuo JWK Set structure
  /// 
  /// Checks that the JWK Set contains exactly 2 keys (signing + encryption)
  /// with proper structure. Does not validate individual key contents.
  /// 
  /// Throws [FormatException] if structure is invalid.
  static void validateKeyDuoJwkStructure(Map<String, dynamic> jwkSet) {
    if (!jwkSet.containsKey('keys')) {
      throw const FormatException('JWK Set must contain "keys" array');
    }

    final dynamic keys = jwkSet['keys'];
    if (keys is! List) {
      throw const FormatException('JWK Set "keys" must be an array');
    }

    if (keys.length != 2) {
      throw const FormatException('JWK Set must contain exactly 2 keys');
    }

    Map<String, dynamic>? signingKeyData;
    Map<String, dynamic>? encryptionKeyData;

    for (final dynamic key in keys) {
      if (key is! Map<String, dynamic>) {
        throw const FormatException('Each key in JWK Set must be an object');
      }

      final String? use = key['use'] as String?;
      if (use == JwkUse.signature) {
        if (signingKeyData != null) {
          throw const FormatException('JWK Set contains multiple signing keys');
        }
        signingKeyData = key;
      } else if (use == JwkUse.encryption) {
        if (encryptionKeyData != null) {
          throw const FormatException('JWK Set contains multiple encryption keys');
        }
        encryptionKeyData = key;
      } else {
        throw const FormatException('Invalid key use. Must be "sig" or "enc"');
      }
    }

    if (signingKeyData == null) {
      throw const FormatException('JWK Set must contain a signing key (use="sig")');
    }

    if (encryptionKeyData == null) {
      throw const FormatException('JWK Set must contain an encryption key (use="enc")');
    }
  }

  /// Validate ECDSA key structure
  /// 
  /// Validates that the key has proper ECDSA P-256 structure with required fields.
  /// 
  /// [keyData] - The JWK key object to validate
  /// [requirePrivateKey] - Whether private key material (d) is required
  /// 
  /// Throws [FormatException] if key structure is invalid.
  static void validateEcdsaKey(Map<String, dynamic> keyData, {required bool requirePrivateKey}) {
    final String? kty = keyData['kty'] as String?;
    if (kty != JwkKeyType.ec) {
      throw const FormatException('Signing key must have type "EC"');
    }

    final String? crv = keyData['crv'] as String?;
    if (crv != JwkCurve.p256) {
      throw const FormatException('Signing key must use curve "P-256"');
    }

    final String? alg = keyData['alg'] as String?;
    if (alg != JwkAlgorithm.es256) {
      throw const FormatException('Signing key must have algorithm "ES256"');
    }

    final String? use = keyData['use'] as String?;
    if (use != JwkUse.signature) {
      throw const FormatException('Signing key must have use "sig"');
    }

    if (!keyData.containsKey('x') || !keyData.containsKey('y')) {
      throw const FormatException('EC key missing required x/y coordinates');
    }

    if (requirePrivateKey && !keyData.containsKey('d')) {
      throw const FormatException('Private key must contain private component "d"');
    }

    if (!keyData.containsKey('kid')) {
      throw const FormatException('Key must contain key identifier "kid"');
    }
  }

  /// Validate ECDH key structure
  /// 
  /// Validates that the key has proper ECDH P-256 structure with required fields.
  /// 
  /// [keyData] - The JWK key object to validate
  /// [requirePrivateKey] - Whether private key material (d) is required
  /// 
  /// Throws [FormatException] if key structure is invalid.
  static void validateEcdhKey(Map<String, dynamic> keyData, {required bool requirePrivateKey}) {
    final String? kty = keyData['kty'] as String?;
    if (kty != JwkKeyType.ec) {
      throw const FormatException('Encryption key must have type "EC"');
    }

    final String? crv = keyData['crv'] as String?;
    if (crv != JwkCurve.p256) {
      throw const FormatException('Encryption key must use curve "P-256"');
    }

    final String? alg = keyData['alg'] as String?;
    if (alg != JwkAlgorithm.ecdhEs256) {
      throw const FormatException('Encryption key must have algorithm "ECDH-ES+A256KW"');
    }

    final String? use = keyData['use'] as String?;
    if (use != JwkUse.encryption) {
      throw const FormatException('Encryption key must have use "enc"');
    }

    if (!keyData.containsKey('x') || !keyData.containsKey('y')) {
      throw const FormatException('EC key missing required x/y coordinates');
    }

    if (requirePrivateKey && !keyData.containsKey('d')) {
      throw const FormatException('Private key must contain private component "d"');
    }

    if (!keyData.containsKey('kid')) {
      throw const FormatException('Key must contain key identifier "kid"');
    }
  }

  /// Validate symmetric key JWK structure
  /// 
  /// Validates that the key has proper AES-GCM structure.
  /// 
  /// [keyData] - The JWK key object to validate
  /// 
  /// Throws [FormatException] if key structure is invalid.
  static void validateSymmetricKeyJwk(Map<String, dynamic> keyData) {
    final String? kty = keyData['kty'] as String?;
    if (kty != 'oct') {
      throw const FormatException('Symmetric key must have type "oct"');
    }

    if (!keyData.containsKey('k')) {
      throw const FormatException('Symmetric key missing required "k" component');
    }
  }

  /// Validate no private key material in JWK Set
  /// 
  /// Ensures that a JWK Set intended for public use contains no private key material.
  /// Useful when importing public-only KeyDuo to prevent accidental private key exposure.
  /// 
  /// [jwkSet] - The JWK Set to validate
  /// 
  /// Throws [FormatException] if private key material is found.
  static void validateNoPrivateKeyMaterial(Map<String, dynamic> jwkSet) {
    final dynamic keys = jwkSet['keys'];
    if (keys is List) {
      for (final dynamic key in keys) {
        if (key is Map<String, dynamic>) {
          const List<String> privateKeyComponents = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'];
          final List<String> foundComponents = <String>[];

          for (final String component in privateKeyComponents) {
            if (key.containsKey(component)) {
              foundComponents.add(component);
            }
          }

          if (foundComponents.isNotEmpty) {
            throw FormatException(
              'Private key material detected: ${foundComponents.join(', ')}. '
              'Use importKeyDuo() for private keys.',
            );
          }
        }
      }
    }
  }

  /// Validate KeyDuo JWK from JSON string
  /// 
  /// Convenience method that parses JSON and validates KeyDuo structure.
  /// 
  /// [jwkSetJson] - JSON string containing JWK Set
  /// 
  /// Throws [FormatException] if JSON is invalid or structure is wrong.
  static void validateKeyDuoJwk(String jwkSetJson) {
    final Map<String, dynamic> jwkSet;
    try {
      jwkSet = jsonDecode(jwkSetJson) as Map<String, dynamic>;
    } catch (e) {
      throw const FormatException('Invalid JSON format');
    }

    validateKeyDuoJwkStructure(jwkSet);
    
    // Extract and validate individual keys
    final List<dynamic> keys = jwkSet['keys'] as List<dynamic>;
    for (final dynamic key in keys) {
      final Map<String, dynamic> keyData = key as Map<String, dynamic>;
      final String? use = keyData['use'] as String?;
      
      if (use == JwkUse.signature) {
        validateEcdsaKey(keyData, requirePrivateKey: false);
      } else if (use == JwkUse.encryption) {
        validateEcdhKey(keyData, requirePrivateKey: false);
      }
    }
  }

  /// Validate symmetric key JWK from JSON string
  /// 
  /// Convenience method that parses JSON and validates symmetric key structure.
  /// 
  /// [jwk] - JSON string containing symmetric key JWK
  /// 
  /// Throws [FormatException] if JSON is invalid or structure is wrong.
  static void validateSymmetricKeyJwkString(String jwk) {
    final Map<String, dynamic> keyData;
    try {
      keyData = jsonDecode(jwk) as Map<String, dynamic>;
    } catch (e) {
      throw const FormatException('Invalid JSON format');
    }

    validateSymmetricKeyJwk(keyData);
  }
}