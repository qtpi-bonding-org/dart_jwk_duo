/// Serialization and import/export functionality for KeyDuo.
library;

import 'dart:convert';
import 'bridge/api.dart' as r;
import 'errors.dart';
import 'generation_service.dart' show keyDuoFromParts;
import 'init.dart';
import 'interfaces.dart';
import 'key_duo.dart';
import 'exported_jwk.dart';
import 'public_key_hex.dart';

/// Interface for serializing and deserializing KeyDuo instances.
abstract class IKeyDuoSerializer {
  /// Exports a KeyDuo as a JWK Set containing private keys.
  Future<String> exportKeyDuoJwk(IKeyDuo duo);

  /// Exports a KeyDuo as a JWK Set containing only public keys.
  Future<String> exportPublicKeyDuoJwk(IKeyDuo duo);

  /// Imports a KeyDuo from a JWK Set JSON string containing private keys.
  Future<KeyDuo> importKeyDuoJwk(String jwkSetJson);

  /// Imports a public-only KeyDuo from a JWK Set JSON string.
  Future<KeyDuo> importPublicKeyDuoJwk(String jwkSetJson);
}

/// Implementation of IKeyDuoSerializer with validation and type safety.
class KeyDuoSerializer implements IKeyDuoSerializer {
  /// Creates a new KeyDuoSerializer.
  const KeyDuoSerializer();

  @override
  Future<String> exportKeyDuoJwk(IKeyDuo duo) async {
    final ExportedJwk signingJwk = await duo.signing.exportPrivateKey();
    final ExportedJwk encryptionJwk = await duo.encryption.exportPrivateKey();

    final Map<String, dynamic> jwkSet = <String, dynamic>{
      'keys': <Map<String, dynamic>>[signingJwk.toJson(), encryptionJwk.toJson()],
    };

    return jsonEncode(jwkSet);
  }

  @override
  Future<String> exportPublicKeyDuoJwk(IKeyDuo duo) async {
    final ExportedJwk signingJwk = await duo.signing.exportPublicKey();
    final ExportedJwk encryptionJwk = await duo.encryption.exportPublicKey();

    final Map<String, dynamic> jwkSet = <String, dynamic>{
      'keys': <Map<String, dynamic>>[signingJwk.toJson(), encryptionJwk.toJson()],
    };

    return jsonEncode(jwkSet);
  }

  @override
  Future<KeyDuo> importKeyDuoJwk(String jwkSetJson) async {
    await ensureInitialized();
    return keyDuoFromParts(rethrowAsDart(() => r.importKeyDuoJwk(json: jwkSetJson)));
  }

  @override
  Future<KeyDuo> importPublicKeyDuoJwk(String jwkSetJson) async {
    await ensureInitialized();
    return keyDuoFromParts(rethrowAsDart(() => r.importPublicKeyDuoJwk(json: jwkSetJson)));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Static Utility Methods
  // ═══════════════════════════════════════════════════════════════════════════

  /// Extract the signing public key from JWK Set JSON as SEC1 hex.
  ///
  /// Returns a 130-char SEC1 uncompressed hex string (`04 || x || y`).
  /// This is the canonical way to derive an account identifier from a
  /// KeyDuo JWK.
  ///
  /// Throws [FormatException] if the JWK is invalid or has no signing key.
  static Future<SigningPublicKeyHex> extractSigningPublicKeySec1Hex(
      String jwkSetJson) async {
    final KeyDuo keyDuo = await const KeyDuoSerializer().importPublicKeyDuoJwk(jwkSetJson);
    try {
      return await keyDuo.signingKeyPair.exportPublicKeySec1Hex();
    } finally {
      keyDuo.dispose();
    }
  }

  /// Extract the encryption public key from JWK Set JSON as SEC1 hex.
  ///
  /// Returns a 130-char SEC1 uncompressed hex string (`04 || x || y`) — the
  /// same encoding as [extractSigningPublicKeySec1Hex], so the two are
  /// interchangeable at the encoding boundary and only distinguishable by
  /// which method produced them.
  ///
  /// Throws [FormatException] if the JWK is invalid or has no encryption key.
  static Future<EncryptionPublicKeyHex> extractEncryptionPublicKeySec1Hex(
      String jwkSetJson) async {
    final KeyDuo keyDuo = await const KeyDuoSerializer().importPublicKeyDuoJwk(jwkSetJson);
    try {
      return await keyDuo.encryptionKeyPair.exportPublicKeySec1Hex();
    } finally {
      keyDuo.dispose();
    }
  }

  /// Extract both public keys from JWK Set JSON as a typed [PublicKeyDuo].
  ///
  /// Prefer this over the two single-key extractors when you need both, so
  /// the pair cannot be assembled with the keys transposed.
  ///
  /// Throws [FormatException] if the JWK is invalid or missing either key.
  static Future<PublicKeyDuo> extractPublicKeyDuo(String jwkSetJson) async {
    final KeyDuo keyDuo = await const KeyDuoSerializer().importPublicKeyDuoJwk(jwkSetJson);
    try {
      return await keyDuo.exportPublicKeyDuo();
    } finally {
      keyDuo.dispose();
    }
  }
}
