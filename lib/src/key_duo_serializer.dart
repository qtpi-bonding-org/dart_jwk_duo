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
import 'verification_service.dart';
import 'validation_service.dart';

/// Interface for serializing and deserializing KeyDuo instances.
abstract class IKeyDuoSerializer {
  /// Exports a KeyDuo as a JWK Set containing private keys.
  Future<String> exportKeyDuo(IKeyDuo duo);

  /// Exports a KeyDuo as a JWK Set containing only public keys.
  Future<String> exportPublicKeyDuo(IKeyDuo duo);

  /// Imports a KeyDuo from a JWK Set JSON string containing private keys.
  Future<KeyDuo> importKeyDuo(String jwkSetJson);

  /// Imports a public-only KeyDuo from a JWK Set JSON string.
  Future<KeyDuo> importPublicKeyDuo(String jwkSetJson);
}

/// Implementation of IKeyDuoSerializer with validation and type safety.
class KeyDuoSerializer implements IKeyDuoSerializer {
  /// Creates a new KeyDuoSerializer.
  const KeyDuoSerializer();

  @override
  Future<String> exportKeyDuo(IKeyDuo duo) async {
    final ExportedJwk signingJwk = await duo.signing.exportPrivateKey();
    final ExportedJwk encryptionJwk = await duo.encryption.exportPrivateKey();

    final Map<String, dynamic> jwkSet = {
      'keys': [signingJwk.toJson(), encryptionJwk.toJson()],
    };

    return jsonEncode(jwkSet);
  }

  @override
  Future<String> exportPublicKeyDuo(IKeyDuo duo) async {
    final ExportedJwk signingJwk = await duo.signing.exportPublicKey();
    final ExportedJwk encryptionJwk = await duo.encryption.exportPublicKey();

    final Map<String, dynamic> jwkSet = {
      'keys': [signingJwk.toJson(), encryptionJwk.toJson()],
    };

    return jsonEncode(jwkSet);
  }

  @override
  Future<KeyDuo> importKeyDuo(String jwkSetJson) async {
    final Map<String, dynamic> jwkSet;
    try {
      jwkSet = jsonDecode(jwkSetJson) as Map<String, dynamic>;
    } catch (e) {
      throw const FormatException('Invalid JSON format');
    }

    return _importKeyDuoFromMap(jwkSet, requirePrivateKeys: true);
  }

  @override
  Future<KeyDuo> importPublicKeyDuo(String jwkSetJson) async {
    final Map<String, dynamic> jwkSet;
    try {
      jwkSet = jsonDecode(jwkSetJson) as Map<String, dynamic>;
    } catch (e) {
      throw const FormatException('Invalid JSON format');
    }

    ValidationService.validateNoPrivateKeyMaterial(jwkSet);
    return _importKeyDuoFromMap(jwkSet, requirePrivateKeys: false);
  }

  Future<KeyDuo> _importKeyDuoFromMap(
    Map<String, dynamic> jwkSet, {
    required bool requirePrivateKeys,
  }) async {
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

    // Import ECDSA signing key
    ValidationService.validateEcdsaKey(signingKeyData, requirePrivateKey: requirePrivateKeys);
    final SigningKeyPair signingKeyPair = await _importEcdsaSigningKey(
      signingKeyData,
      requirePrivateKeys,
    );

    // Import ECDH encryption key
    ValidationService.validateEcdhKey(encryptionKeyData, requirePrivateKey: requirePrivateKeys);
    final EncryptionKeyPair encryptionKeyPair = await _importEcdhEncryptionKey(
      encryptionKeyData,
      requirePrivateKeys,
    );

    return KeyDuo(signing: signingKeyPair, encryption: encryptionKeyPair);
  }

  Future<SigningKeyPair> _importEcdsaSigningKey(
    Map<String, dynamic> keyData,
    bool requirePrivateKey,
  ) async {
    if (requirePrivateKey) {
      final EcdsaPrivateKey privateKey = await EcdsaPrivateKey.importJsonWebKey(
        keyData,
        EllipticCurve.p256,
      );
      final Map<String, dynamic> publicKeyData = Map<String, dynamic>.from(keyData)..remove('d');
      final EcdsaPublicKey publicKey = await EcdsaPublicKey.importJsonWebKey(
        publicKeyData,
        EllipticCurve.p256,
      );
      return SigningKeyPair(privateKey: privateKey, publicKey: publicKey);
    } else {
      final EcdsaPublicKey publicKey = await EcdsaPublicKey.importJsonWebKey(
        keyData,
        EllipticCurve.p256,
      );
      return SigningKeyPair.publicOnly(publicKey: publicKey);
    }
  }

  Future<EncryptionKeyPair> _importEcdhEncryptionKey(
    Map<String, dynamic> keyData,
    bool requirePrivateKey,
  ) async {
    // Remove 'use' field to avoid WebCrypto compatibility issues
    // ECDH keys exported by WebCrypto omit 'use' field, but our JWKs include it
    final keyDataCopy = Map<String, dynamic>.from(keyData);
    keyDataCopy.remove('use');
    
    if (requirePrivateKey) {
      final EcdhPrivateKey privateKey = await EcdhPrivateKey.importJsonWebKey(
        keyDataCopy, EllipticCurve.p256);
      final Map<String, dynamic> publicKeyData = Map<String, dynamic>.from(keyDataCopy)..remove('d');
      final EcdhPublicKey publicKey = await EcdhPublicKey.importJsonWebKey(
        publicKeyData, EllipticCurve.p256);
      return EncryptionKeyPair(privateKey: privateKey, publicKey: publicKey);
    } else {
      final EcdhPublicKey publicKey = await EcdhPublicKey.importJsonWebKey(
        keyDataCopy, EllipticCurve.p256);
      return EncryptionKeyPair.publicOnly(publicKey: publicKey);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Static Utility Methods
  // ═══════════════════════════════════════════════════════════════════════════

  /// Verifies a JWK Set is valid and keys work.
  /// 
  /// Performs full verification:
  /// 1. Parses JSON and validates structure
  /// 2. Imports keys via webcrypto
  /// 3. Runs cryptographic roundtrips (sign/verify, encrypt/decrypt)
  /// 
  /// Returns the verified [KeyDuo] on success.
  /// Throws [FormatException] if structure is invalid.
  /// Throws [StateError] if keys don't have private material.
  /// Throws [StateError] if cryptographic verification fails.
  static Future<KeyDuo> verifyJwk(String jwkSetJson) async {
    const KeyDuoSerializer serializer = KeyDuoSerializer();
    final KeyDuo keyDuo = await serializer.importKeyDuo(jwkSetJson);
    
    // Use VerificationService instead of removed KeyDuo.verify()
    final bool verified = await VerificationService.verifyKeyDuo(keyDuo);
    if (!verified) {
      throw StateError('Key verification failed: cryptographic roundtrip test failed');
    }
    
    return keyDuo;
  }

  /// Extract signing public key hex from JWK Set JSON.
  /// 
  /// Returns 128-char hex string (x + y coordinates, no 04 prefix).
  /// This is the canonical way to derive an account identifier from a KeyDuo JWK.
  /// 
  /// The hex is derived by:
  /// 1. Importing the JWK Set via webcrypto (validates the key)
  /// 2. Exporting the signing public key as raw bytes
  /// 3. Converting to lowercase hex (no 04 prefix)
  /// 
  /// This goes through the full webcrypto import/export path to ensure
  /// the hex matches what [SigningKeyPair.exportPublicKeyHex] produces.
  /// 
  /// Throws [FormatException] if JWK is invalid or missing signing key.
  static Future<String> extractSigningPublicKeyHex(String jwkSetJson) async {
    // Reuse the existing import logic - this validates the JWK structure
    // and imports via webcrypto
    const serializer = KeyDuoSerializer();
    
    // Import as public-only to avoid requiring private key material
    // (we only need the public key to get the hex)
    KeyDuo keyDuo;
    try {
      // Try public-only first (works for both public and private JWKs
      // since we strip private material during import)
      keyDuo = await serializer._importKeyDuoFromMap(
        jsonDecode(jwkSetJson) as Map<String, dynamic>,
        requirePrivateKeys: false,
      );
    } catch (e) {
      if (e is FormatException) rethrow;
      throw FormatException('Invalid JWK Set: $e');
    }
    
    // Use the concrete SigningKeyPair's exportPublicKeyHex()
    return await keyDuo.signingKeyPair.exportPublicKeyHex();
  }
}
