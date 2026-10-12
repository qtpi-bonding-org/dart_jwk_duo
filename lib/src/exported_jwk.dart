/// Data Transfer Object for type-safe JWK export with guaranteed metadata.
library;

import 'dart:convert';
import 'constants.dart';

/// A fully typed export object that guarantees metadata is attached to the key
/// before it becomes JSON.
///
/// Instances come from the key pairs' export methods; there is no public
/// constructor.
class ExportedJwk {
  ExportedJwk._({
    required Map<String, dynamic> keyData,
    required this.keyId,
    required this.alg,
    required this.use,
  }) : _keyData = Map<String, dynamic>.unmodifiable(keyData);

  /// The underlying JWK data as a Map
  final Map<String, dynamic> _keyData;

  /// Key identifier (kid) - RFC 7638 JWK thumbprint used for key lookup
  final String keyId;

  /// Algorithm (alg): `ES256` for signing keys, `HPKE-7` for encryption keys
  final String alg;

  /// Public key use (use) - either 'sig' for signing or 'enc' for encryption
  final String use;

  /// Converts the ExportedJwk to a JSON Map.
  ///
  /// Merges the raw key data with the metadata (kid, alg, use).
  Map<String, dynamic> toJson() {
    final Map<String, dynamic> result = Map<String, dynamic>.from(_keyData);
    result['kid'] = keyId;
    result['alg'] = alg;
    result['use'] = use;
    return result;
  }

  /// Creates a public-only version of this ExportedJwk.
  ///
  /// Copies kty, crv, x, y, kid, alg and use.
  ExportedJwk toPublicOnly() {
    if (_keyData['kty'] != JwkKeyType.ec) {
      throw const FormatException('Unknown key type');
    }

    final Map<String, dynamic> publicKeyData = <String, dynamic>{
      'kty': _keyData['kty'],
      'crv': _keyData['crv'],
      'x': _keyData['x'],
      'y': _keyData['y'],
    };

    if (publicKeyData.containsValue(null)) {
      throw const FormatException('Cannot create public key: missing required components');
    }

    return ExportedJwk._(
      keyData: publicKeyData,
      keyId: keyId,
      alg: alg,
      use: use,
    );
  }
}

/// Builds an [ExportedJwk] from the JWK JSON the native library emits.
///
/// Internal: the barrel exports only the `ExportedJwk` type.
ExportedJwk exportedJwkFromJson(String json) {
  final Object? decoded;
  try {
    decoded = jsonDecode(json);
  } on FormatException {
    throw const FormatException('Invalid JSON format');
  }
  if (decoded is! Map<String, dynamic>) {
    throw const FormatException('JWK must be a JSON object');
  }
  final Object? kid = decoded['kid'];
  final Object? alg = decoded['alg'];
  final Object? use = decoded['use'];
  if (kid is! String || alg is! String || use is! String) {
    throw const FormatException('JWK must carry string "kid", "alg" and "use"');
  }
  final Map<String, dynamic> keyData = Map<String, dynamic>.from(decoded)
    ..remove('kid')
    ..remove('alg')
    ..remove('use');
  return ExportedJwk._(keyData: keyData, keyId: kid, alg: alg, use: use);
}
