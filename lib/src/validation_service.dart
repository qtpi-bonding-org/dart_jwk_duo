/// Service for structural JWK validation (format checks).
library;

import 'dart:convert';
import 'bridge/api.dart' as r;
import 'errors.dart';
import 'init.dart';

/// Service for structural JWK validation (format checks only)
///
/// Validates JWK structure and required fields without performing
/// cryptographic operations. Use VerificationService for crypto roundtrip
/// tests. The checks run in rust_jwk_duo; the `Map` parameters are
/// JSON-encoded before crossing the bridge.
///
/// Every method throws [FormatException] on invalid input.
class ValidationService {
  /// Validate KeyDuo JWK Set structure: exactly 2 keys with proper structure.
  /// Does not validate individual key contents.
  static Future<void> validateKeyDuoJwkStructure(Map<String, dynamic> jwkSet) async {
    await ensureInitialized();
    rethrowAsDart(() => r.validateKeyDuoJwkStructure(setJson: encodeJsonArg(jwkSet)));
  }

  /// Validate an ECDSA P-256 signing JWK.
  ///
  /// [requirePrivateKey] - Whether private key material (d) is required
  static Future<void> validateEcdsaKey(Map<String, dynamic> keyData, {required bool requirePrivateKey}) async {
    await ensureInitialized();
    rethrowAsDart(() => r.validateSigningKey(
        keyJson: encodeJsonArg(keyData), requirePrivate: requirePrivateKey));
  }

  /// Validate a P-256 encryption JWK (alg `HPKE-7`).
  ///
  /// [requirePrivateKey] - Whether private key material (d) is required
  static Future<void> validateEcdhKey(Map<String, dynamic> keyData, {required bool requirePrivateKey}) async {
    await ensureInitialized();
    rethrowAsDart(() => r.validateEncryptionKey(
        keyJson: encodeJsonArg(keyData), requirePrivate: requirePrivateKey));
  }

  /// Validate an AES-GCM symmetric key JWK.
  static Future<void> validateSymmetricKeyJwk(Map<String, dynamic> keyData) async {
    await ensureInitialized();
    rethrowAsDart(() => r.validateSymmetricKeyJwk(keyJson: encodeJsonArg(keyData)));
  }

  /// Extract only public EC key fields from a raw JWK map.
  ///
  /// Returns a new map containing only the public fields: kty, crv, x, y,
  /// alg, use, kid. Private key material is never copied.
  static Map<String, dynamic> extractPublicKeyFields(Map<String, dynamic> key) {
    return <String, dynamic>{
      if (key.containsKey('kty')) 'kty': key['kty'],
      if (key.containsKey('crv')) 'crv': key['crv'],
      if (key.containsKey('x')) 'x': key['x'],
      if (key.containsKey('y')) 'y': key['y'],
      if (key.containsKey('alg')) 'alg': key['alg'],
      if (key.containsKey('use')) 'use': key['use'],
      if (key.containsKey('kid')) 'kid': key['kid'],
    };
  }

  /// Extract a public-only JWK Set from a JWK Set that may contain private keys.
  static Future<Map<String, dynamic>> extractPublicKeySet(Map<String, dynamic> jwkSet) async {
    await ensureInitialized();
    final String out =
        rethrowAsDart(() => r.extractPublicKeySet(setJson: encodeJsonArg(jwkSet)));
    return jsonDecode(out) as Map<String, dynamic>;
  }

  /// Validate that a JWK Set holds no private key material.
  static Future<void> validateNoPrivateKeyMaterial(Map<String, dynamic> jwkSet) async {
    await ensureInitialized();
    rethrowAsDart(() => r.validateNoPrivateKeyMaterial(setJson: encodeJsonArg(jwkSet)));
  }

  /// Validate a KeyDuo JWK Set given as a JSON string.
  static Future<void> validateKeyDuoJwk(String jwkSetJson) async {
    await ensureInitialized();
    rethrowAsDart(() => r.validateKeyDuoJwk(setJson: jwkSetJson));
  }

  /// Validate a symmetric key JWK given as a JSON string.
  static Future<void> validateSymmetricKeyJwkString(String jwk) async {
    await ensureInitialized();
    rethrowAsDart(() => r.validateSymmetricKeyJwkString(json: jwk));
  }
}
