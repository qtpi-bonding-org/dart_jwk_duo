/// Type-safe wrapper for ECDSA P-256 signing key pairs.
library;

import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';
import 'interfaces.dart';
import 'exported_jwk.dart';
import 'constants.dart';
import 'jwk_thumbprint.dart';
import 'public_key_hex.dart';
import 'sec1_public_key.dart';

/// Type-safe wrapper for ECDSA P-256 signing key pairs.
/// 
/// Provides compile-time safety by restricting operations to signing keys only.
/// Uses ES256 algorithm (ECDSA with P-256 curve and SHA-256).
class SigningKeyPair implements IKeyPair<EcdsaPrivateKey, EcdsaPublicKey> {
  final EcdsaPrivateKey? _privateKey;
  final EcdsaPublicKey _publicKey;
  
  /// Creates a new SigningKeyPair wrapper with both private and public keys.
  SigningKeyPair({
    required EcdsaPrivateKey privateKey,
    required EcdsaPublicKey publicKey,
  }) : _privateKey = privateKey,
       _publicKey = publicKey;

  /// Creates a new public-only SigningKeyPair wrapper.
  SigningKeyPair.publicOnly({
    required EcdsaPublicKey publicKey,
  }) : _privateKey = null,
       _publicKey = publicKey;

  // ═══════════════════════════════════════════════════════════════════════════
  // Static Import Methods
  // ═══════════════════════════════════════════════════════════════════════════

  /// Import a public-only SigningKeyPair from SEC1 uncompressed hex.
  ///
  /// Takes a [SigningPublicKeyHex] rather than a bare `String` so that an
  /// encryption key cannot be imported here by accident — the two are
  /// byte-indistinguishable, so the type is the only thing that can tell them
  /// apart. Wrap a value read from storage explicitly:
  /// `SigningPublicKeyHex(hexFromDatabase)`.
  ///
  /// This is the inverse of [exportPublicKeySec1Hex].
  ///
  /// Use case: verify signatures when all you have is the public key hex.
  ///
  /// Throws [FormatException] if the bytes do not describe a point on P-256.
  static Future<SigningKeyPair> importPublicKeySec1Hex(
      SigningPublicKeyHex sec1Hex) async {
    return importPublicKeyRaw(Sec1PublicKey.decodeHex(sec1Hex.value));
  }

  /// Import a public-only SigningKeyPair from SEC1 uncompressed bytes.
  ///
  /// [raw] must be exactly 65 bytes: the `04` tag followed by the 32-byte x
  /// and 32-byte y coordinates. This is the inverse of [exportPublicKeyRaw].
  ///
  /// Throws [FormatException] if the length or tag is wrong, or if the bytes
  /// do not describe a point on P-256.
  static Future<SigningKeyPair> importPublicKeyRaw(Uint8List raw) async {
    final EcdsaPublicKey publicKey = await EcdsaPublicKey.importRawKey(
      Sec1PublicKey.validateRaw(raw), EllipticCurve.p256);

    return SigningKeyPair.publicOnly(publicKey: publicKey);
  }

  @override
  EcdsaPrivateKey? get privateKey => _privateKey;

  @override
  EcdsaPublicKey get publicKey => _publicKey;

  @override
  bool get hasPrivateKey => _privateKey != null;

  // ═══════════════════════════════════════════════════════════════════════════
  // Signing Operations (concrete class methods, not in interface)
  // ═══════════════════════════════════════════════════════════════════════════

  /// Sign bytes with the private key.
  Future<Uint8List> signBytes(Uint8List data) async {
    if (_privateKey == null) {
      throw StateError('Cannot sign: public-only key pair');
    }
    return await _privateKey!.signBytes(data, Hash.sha256);
  }

  /// Verify a signature against the original data.
  Future<bool> verifyBytes(Uint8List signature, Uint8List data) async {
    return await _publicKey.verifyBytes(signature, data, Hash.sha256);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // IKeyPair Implementation
  // ═══════════════════════════════════════════════════════════════════════════

  @override
  Future<Uint8List> exportPublicKeyRaw() async {
    return Sec1PublicKey.validateRaw(await _publicKey.exportRawKey());
  }

  /// Export the public key as SEC1 uncompressed hex, typed as a signing key.
  ///
  /// Narrows [IKeyPair.exportPublicKeySec1Hex] from `String` to
  /// [SigningPublicKeyHex]. Same 130 characters either way — the difference is
  /// that the result cannot be assigned to a variable or parameter expecting
  /// an encryption key.
  @override
  Future<SigningPublicKeyHex> exportPublicKeySec1Hex() async {
    return SigningPublicKeyHex(
      Sec1PublicKey.encodeHex(await exportPublicKeyRaw()));
  }

  @override
  Future<ExportedJwk> exportPrivateKey() async {
    if (_privateKey == null) {
      throw StateError('Cannot export private key: public-only key pair');
    }
    
    final Map<String, dynamic> jwkMap = await _privateKey!.exportJsonWebKey();
    final String keyId = await calculateKeyId();
    
    return ExportedJwk(
      keyData: jwkMap,
      keyId: keyId,
      alg: JwkAlgorithm.es256,
      use: JwkUse.signature,
    );
  }

  @override
  Future<ExportedJwk> exportPublicKey() async {
    final Map<String, dynamic> jwkMap = await _publicKey.exportJsonWebKey();
    final String keyId = await calculateKeyId();
    
    return ExportedJwk(
      keyData: jwkMap,
      keyId: keyId,
      alg: JwkAlgorithm.es256,
      use: JwkUse.signature,
    );
  }

  @override
  Future<String> calculateKeyId() async {
    final Map<String, dynamic> jwk = await _publicKey.exportJsonWebKey();
    return calculateJwkThumbprint(jwk);
  }

}
