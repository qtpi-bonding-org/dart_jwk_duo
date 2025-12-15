/// Serialization and import/export functionality for KeyDuo.
library;

import 'dart:convert';
import 'package:webcrypto/webcrypto.dart';
import 'interfaces.dart';
import 'key_duo.dart';
import 'signing_key_pair.dart';
import 'encryption_key_pair.dart';
import 'constants.dart';
import 'exported_jwk.dart';

/// Interface for serializing and deserializing KeyDuo instances.
/// 
/// Provides methods for exporting KeyDuo as JWK Sets (both private and public)
/// and importing KeyDuo from JWK Set JSON strings with proper validation.
abstract class IKeyDuoSerializer {
  /// Exports a KeyDuo as a JWK Set containing private keys.
  /// 
  /// Returns a JSON string containing both signing and encryption key pairs
  /// with all RSA components including private exponents.
  /// 
  /// [duo] - The KeyDuo to export
  /// Returns a JSON string in RFC 7517 JWK Set format
  Future<String> exportKeyDuo(IKeyDuo duo);
  
  /// Exports a KeyDuo as a JWK Set containing only public keys.
  /// 
  /// Returns a JSON string containing both signing and encryption key pairs
  /// with only public RSA components (no private exponents).
  /// 
  /// [duo] - The KeyDuo to export
  /// Returns a JSON string in RFC 7517 JWK Set format (public keys only)
  Future<String> exportPublicKeyDuo(IKeyDuo duo);
  
  /// Imports a KeyDuo from a JWK Set JSON string containing private keys.
  /// 
  /// Parses the JSON, validates the structure, and creates a new KeyDuo
  /// with properly typed signing and encryption key pairs.
  /// 
  /// [jwkSetJson] - JSON string containing a JWK Set with private keys
  /// Returns a KeyDuo with imported key pairs
  /// Throws [FormatException] if validation fails
  Future<IKeyDuo> importKeyDuo(String jwkSetJson);
  
  /// Imports a public-only KeyDuo from a JWK Set JSON string.
  /// 
  /// Parses the JSON, validates the structure, and creates a new KeyDuo
  /// with public keys only. Useful for signature verification and encryption.
  /// 
  /// [jwkSetJson] - JSON string containing a JWK Set with public keys only
  /// Returns a KeyDuo with public key pairs only
  /// Throws [FormatException] if validation fails
  Future<IKeyDuo> importPublicKeyDuo(String jwkSetJson);
}

/// Implementation of IKeyDuoSerializer with validation and type safety.
/// 
/// Handles export/import of KeyDuo instances with proper validation of
/// RSA key types, use fields, and private exponent presence.
class KeyDuoSerializer implements IKeyDuoSerializer {
  /// Creates a new KeyDuoSerializer.
  /// 
  /// Uses standard RFC 7638 thumbprints for key identifiers.
  const KeyDuoSerializer();
  
  @override
  Future<String> exportKeyDuo(IKeyDuo duo) async {
    // Export both key pairs with private components
    final ExportedJwk signingJwk = await duo.signing.exportPrivateKey();
    final ExportedJwk encryptionJwk = await duo.encryption.exportPrivateKey();
    
    // Create JWK Set structure
    final Map<String, List<Map<String, dynamic>>> jwkSet = <String, List<Map<String, dynamic>>>{
      'keys': <Map<String, dynamic>>[
        signingJwk.toJson(),
        encryptionJwk.toJson(),
      ],
    };
    
    return jsonEncode(jwkSet);
  }
  
  @override
  Future<String> exportPublicKeyDuo(IKeyDuo duo) async {
    // Export both key pairs with only public components
    final ExportedJwk signingJwk = await duo.signing.exportPublicKey();
    final ExportedJwk encryptionJwk = await duo.encryption.exportPublicKey();
    
    // Create JWK Set structure
    final Map<String, List<Map<String, dynamic>>> jwkSet = <String, List<Map<String, dynamic>>>{
      'keys': <Map<String, dynamic>>[
        signingJwk.toJson(),
        encryptionJwk.toJson(),
      ],
    };
    
    return jsonEncode(jwkSet);
  }
  
  @override
  Future<IKeyDuo> importKeyDuo(String jwkSetJson) async {
    // Parse JSON once
    final Map<String, dynamic> jwkSet;
    try {
      jwkSet = jsonDecode(jwkSetJson) as Map<String, dynamic>;
    } catch (e) {
      throw const FormatException('Invalid JSON format');
    }
    
    return _importKeyDuoFromMap(jwkSet, requirePrivateKeys: true);
  }
  
  @override
  Future<IKeyDuo> importPublicKeyDuo(String jwkSetJson) async {
    // Parse JSON once and validate for private key material
    final Map<String, dynamic> jwkSet;
    try {
      jwkSet = jsonDecode(jwkSetJson) as Map<String, dynamic>;
    } catch (e) {
      throw const FormatException('Invalid JSON format');
    }
    
    // Check for private key material in public-only import
    _validateNoPrivateKeyMaterial(jwkSet);
    return _importKeyDuoFromMap(jwkSet, requirePrivateKeys: false);
  }
  
  /// Internal method for importing key duos from parsed JSON with configurable private key requirement.
  Future<IKeyDuo> _importKeyDuoFromMap(Map<String, dynamic> jwkSet, {required bool requirePrivateKeys}) async {
    
    // Validate JWK Set structure
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
    
    // Find signing and encryption keys by use field
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
    
    // Validate and import signing key
    _validateSigningKey(signingKeyData, requirePrivateKey: requirePrivateKeys);
    final RsaPssPublicKey signingPublicKey = await RsaPssPublicKey.importJsonWebKey(
      signingKeyData,
      Hash.sha256,
    );
    
    SigningKeyPair signingKeyPair;
    if (requirePrivateKeys) {
      final RsaPssPrivateKey signingPrivateKey = await RsaPssPrivateKey.importJsonWebKey(
        signingKeyData,
        Hash.sha256,
      );
      signingKeyPair = SigningKeyPair(
        privateKey: signingPrivateKey,
        publicKey: signingPublicKey,
      );
    } else {
      // For public-only import, create a key pair with null private key
      signingKeyPair = SigningKeyPair.publicOnly(
        publicKey: signingPublicKey,
      );
    }
    
    // Validate and import encryption key
    _validateEncryptionKey(encryptionKeyData, requirePrivateKey: requirePrivateKeys);
    final RsaOaepPublicKey encryptionPublicKey = await RsaOaepPublicKey.importJsonWebKey(
      encryptionKeyData,
      Hash.sha256,
    );
    
    EncryptionKeyPair encryptionKeyPair;
    if (requirePrivateKeys) {
      final RsaOaepPrivateKey encryptionPrivateKey = await RsaOaepPrivateKey.importJsonWebKey(
        encryptionKeyData,
        Hash.sha256,
      );
      encryptionKeyPair = EncryptionKeyPair(
        privateKey: encryptionPrivateKey,
        publicKey: encryptionPublicKey,
      );
    } else {
      // For public-only import, create a key pair with null private key
      encryptionKeyPair = EncryptionKeyPair.publicOnly(
        publicKey: encryptionPublicKey,
      );
    }
    
    return KeyDuo(
      signing: signingKeyPair,
      encryption: encryptionKeyPair,
    );
  }
  
  /// Validates a signing key's structure and metadata.
  /// 
  /// Throws [FormatException] if validation fails.
  void _validateSigningKey(Map<String, dynamic> keyData, {required bool requirePrivateKey}) {
    _validateRsaKey(keyData, requirePrivateKey: requirePrivateKey);
    
    // Validate algorithm
    final String? alg = keyData['alg'] as String?;
    if (alg != JwkAlgorithm.ps256) {
      throw const FormatException('Signing key must have algorithm "PS256"');
    }
    
    // Validate use
    final String? use = keyData['use'] as String?;
    if (use != JwkUse.signature) {
      throw const FormatException('Signing key must have use "sig"');
    }
  }
  
  /// Validates an encryption key's structure and metadata.
  /// 
  /// Throws [FormatException] if validation fails.
  void _validateEncryptionKey(Map<String, dynamic> keyData, {required bool requirePrivateKey}) {
    _validateRsaKey(keyData, requirePrivateKey: requirePrivateKey);
    
    // Validate algorithm
    final String? alg = keyData['alg'] as String?;
    if (alg != JwkAlgorithm.rsaOaep256) {
      throw const FormatException('Encryption key must have algorithm "RSA-OAEP-256"');
    }
    
    // Validate use
    final String? use = keyData['use'] as String?;
    if (use != JwkUse.encryption) {
      throw const FormatException('Encryption key must have use "enc"');
    }
  }
  
  /// Validates that no private key material is present in public-only import.
  /// 
  /// Checks for all RSA private key components as defined in RFC 7518:
  /// - d: private exponent
  /// - p: first prime factor
  /// - q: second prime factor  
  /// - dp: first factor CRT exponent
  /// - dq: second factor CRT exponent
  /// - qi: first CRT coefficient
  /// - oth: other primes info (for multi-prime RSA)
  /// 
  /// Throws [FormatException] if private key material is detected.
  void _validateNoPrivateKeyMaterial(Map<String, dynamic> jwkSet) {
    final dynamic keys = jwkSet['keys'];
    if (keys is List) {
      for (final dynamic key in keys) {
        if (key is Map<String, dynamic>) {
          // Check for all possible RSA private key components (RFC 7518)
          const List<String> privateKeyComponents = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'];
          final List<String> foundComponents = <String>[];
          
          for (final String component in privateKeyComponents) {
            if (key.containsKey(component)) {
              foundComponents.add(component);
            }
          }
          
          if (foundComponents.isNotEmpty) {
            throw FormatException(
              'Private key material detected in public-only import: ${foundComponents.join(', ')}. '
              'Use importKeyDuo() for private keys or remove private key components from JSON.'
            );
          }
        }
      }
    }
  }

  /// Validates common RSA key structure and components.
  /// 
  /// Throws [FormatException] if validation fails.
  void _validateRsaKey(Map<String, dynamic> keyData, {required bool requirePrivateKey}) {
    // Validate key type
    final String? kty = keyData['kty'] as String?;
    if (kty != JwkKeyType.rsa) {
      throw const FormatException('Key must have type "RSA"');
    }
    
    // Validate required RSA components
    final List<String> requiredComponents = <String>['n', 'e'];
    for (final String component in requiredComponents) {
      if (!keyData.containsKey(component)) {
        throw const FormatException('RSA key missing required component');
      }
    }
    
    // Validate private exponent presence for private keys
    if (requirePrivateKey && !keyData.containsKey('d')) {
      throw const FormatException('Private key must contain private exponent "d"');
    }
    
    // Validate kid presence
    if (!keyData.containsKey('kid')) {
      throw const FormatException('Key must contain key identifier "kid"');
    }
  }
}