/// Type-safe wrapper for AES-256-GCM symmetric keys.
library;

import 'dart:convert';
import 'package:webcrypto/webcrypto.dart';

/// Type-safe wrapper for AES-256-GCM symmetric keys
class SymmetricKey {
  final AesGcmSecretKey _key;
  
  SymmetricKey._internal(this._key);
  
  /// Create SymmetricKey from AesGcmSecretKey (internal use)
  /// 
  /// Used by GenerationService and other internal services.
  factory SymmetricKey.fromAesKey(AesGcmSecretKey aesKey) {
    return SymmetricKey._internal(aesKey);
  }
  
  /// Import from JWK string (uses WebCrypto import)
  /// 
  /// Imports a symmetric key from JWK format. No validation is performed -
  /// use ValidationService.validateSymmetricKeyJwk() if validation is needed.
  /// 
  /// [jwk] - JSON string containing symmetric key JWK
  /// 
  /// Returns imported [SymmetricKey].
  /// Throws [FormatException] if import fails.
  static Future<SymmetricKey> fromJwk(String jwk) async {
    try {
      final Map<String, dynamic> jwkMap = jsonDecode(jwk) as Map<String, dynamic>;
      
      // Use WebCrypto's native import (no validation - caller decides when to validate)
      final AesGcmSecretKey aesKey = await AesGcmSecretKey.importJsonWebKey(jwkMap);
      
      return SymmetricKey.fromAesKey(aesKey);
    } catch (e) {
      throw FormatException('Failed to import symmetric key: $e');
    }
  }
  
  /// Export as JWK string (uses WebCrypto export)
  /// 
  /// Exports the symmetric key as JWK format JSON string.
  /// 
  /// Returns JWK JSON string.
  /// Throws [StateError] if export fails.
  Future<String> toJwk() async {
    try {
      // Use WebCrypto's native export (just like KeyDuo does)
      final Map<String, dynamic> jwkMap = await _key.exportJsonWebKey();
      return jsonEncode(jwkMap);
    } catch (e) {
      throw StateError('Failed to export symmetric key: $e');
    }
  }
  
  // Internal access for CryptoService and VerificationService
  AesGcmSecretKey get internal => _key;
}