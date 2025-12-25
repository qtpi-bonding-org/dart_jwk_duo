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
abstract class IKeyDuoSerializer {
  /// Exports a KeyDuo as a JWK Set containing private keys.
  Future<String> exportKeyDuo(IKeyDuo duo);

  /// Exports a KeyDuo as a JWK Set containing only public keys.
  Future<String> exportPublicKeyDuo(IKeyDuo duo);

  /// Imports a KeyDuo from a JWK Set JSON string containing private keys.
  Future<IKeyDuo> importKeyDuo(String jwkSetJson);

  /// Imports a public-only KeyDuo from a JWK Set JSON string.
  Future<IKeyDuo> importPublicKeyDuo(String jwkSetJson);
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
  Future<IKeyDuo> importKeyDuo(String jwkSetJson) async {
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
    final Map<String, dynamic> jwkSet;
    try {
      jwkSet = jsonDecode(jwkSetJson) as Map<String, dynamic>;
    } catch (e) {
      throw const FormatException('Invalid JSON format');
    }

    _validateNoPrivateKeyMaterial(jwkSet);
    return _importKeyDuoFromMap(jwkSet, requirePrivateKeys: false);
  }

  Future<IKeyDuo> _importKeyDuoFromMap(
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
    _validateEcdsaKey(signingKeyData, requirePrivateKey: requirePrivateKeys);
    final SigningKeyPair signingKeyPair = await _importEcdsaSigningKey(
      signingKeyData,
      requirePrivateKeys,
    );

    // Import RSA encryption key
    _validateRsaKey(encryptionKeyData, requirePrivateKey: requirePrivateKeys);
    final EncryptionKeyPair encryptionKeyPair = await _importRsaEncryptionKey(
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

  Future<EncryptionKeyPair> _importRsaEncryptionKey(
    Map<String, dynamic> keyData,
    bool requirePrivateKey,
  ) async {
    final RsaOaepPublicKey publicKey = await RsaOaepPublicKey.importJsonWebKey(
      keyData,
      Hash.sha256,
    );

    if (requirePrivateKey) {
      final RsaOaepPrivateKey privateKey = await RsaOaepPrivateKey.importJsonWebKey(
        keyData,
        Hash.sha256,
      );
      return EncryptionKeyPair(privateKey: privateKey, publicKey: publicKey);
    } else {
      return EncryptionKeyPair.publicOnly(publicKey: publicKey);
    }
  }

  void _validateEcdsaKey(Map<String, dynamic> keyData, {required bool requirePrivateKey}) {
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

  void _validateRsaKey(Map<String, dynamic> keyData, {required bool requirePrivateKey}) {
    final String? kty = keyData['kty'] as String?;
    if (kty != JwkKeyType.rsa) {
      throw const FormatException('Encryption key must have type "RSA"');
    }

    final String? alg = keyData['alg'] as String?;
    if (alg != JwkAlgorithm.rsaOaep256) {
      throw const FormatException('Encryption key must have algorithm "RSA-OAEP-256"');
    }

    final String? use = keyData['use'] as String?;
    if (use != JwkUse.encryption) {
      throw const FormatException('Encryption key must have use "enc"');
    }

    if (!keyData.containsKey('n') || !keyData.containsKey('e')) {
      throw const FormatException('RSA key missing required n/e components');
    }

    if (requirePrivateKey && !keyData.containsKey('d')) {
      throw const FormatException('Private key must contain private exponent "d"');
    }

    if (!keyData.containsKey('kid')) {
      throw const FormatException('Key must contain key identifier "kid"');
    }
  }

  void _validateNoPrivateKeyMaterial(Map<String, dynamic> jwkSet) {
    final dynamic keys = jwkSet['keys'];
    if (keys is List) {
      for (final dynamic key in keys) {
        if (key is Map<String, dynamic>) {
          const List<String> privateKeyComponents = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'];
          final List<String> foundComponents = [];

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
}
