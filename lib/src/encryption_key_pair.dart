/// Type-safe wrapper for ECDH P-256 encryption key pairs.
library;

import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';
import 'interfaces.dart';
import 'exported_jwk.dart';
import 'constants.dart';
import 'jwk_thumbprint.dart';
import 'public_key_hex.dart';
import 'sec1_public_key.dart';

/// Type-safe wrapper for ECDH P-256 encryption key pairs.
/// 
/// Provides compile-time safety by restricting operations to ECDH keys only.
/// Uses ECDH-ES+A256KW algorithm for key agreement and hybrid encryption.
class EncryptionKeyPair implements IKeyPair<EcdhPrivateKey, EcdhPublicKey> {
  final EcdhPrivateKey? _privateKey;
  final EcdhPublicKey _publicKey;
  
  /// Creates a new EncryptionKeyPair wrapper with both private and public keys.
  /// 
  /// **IMPORTANT**: The caller must ensure that [privateKey] and [publicKey] 
  /// are mathematically paired (i.e., they belong to the same ECDH key pair).
  /// This constructor does not validate the key pair relationship due to 
  /// WebCrypto API limitations. Mismatched keys will result in cryptographic
  /// failures during key agreement operations.
  /// 
  /// Use [GenerationService] to safely generate matched key pairs.
  /// 
  /// [privateKey] - The ECDH private key
  /// [publicKey] - The ECDH public key  
  EncryptionKeyPair({
    required EcdhPrivateKey privateKey,
    required EcdhPublicKey publicKey,
  }) : _privateKey = privateKey,
       _publicKey = publicKey;

  /// Creates a new public-only EncryptionKeyPair wrapper.
  /// 
  /// [publicKey] - The ECDH public key  
  EncryptionKeyPair.publicOnly({
    required EcdhPublicKey publicKey,
  }) : _privateKey = null,
       _publicKey = publicKey;

  // ═══════════════════════════════════════════════════════════════════════════
  // Static Import Methods
  // ═══════════════════════════════════════════════════════════════════════════

  /// Import a public-only EncryptionKeyPair from SEC1 uncompressed hex.
  ///
  /// Takes an [EncryptionPublicKeyHex] rather than a bare `String` so that a
  /// signing key cannot be imported here by accident — the two are
  /// byte-indistinguishable, so the type is the only thing that can tell them
  /// apart. Wrap a value read from storage explicitly:
  /// `EncryptionPublicKeyHex(hexFromDatabase)`.
  ///
  /// This is the inverse of [exportPublicKeySec1Hex].
  ///
  /// Use case: encrypt to a recipient when all you have is their public key
  /// hex. The result has no private key, so it can receive data but not
  /// decrypt it.
  ///
  /// Throws [FormatException] if the bytes do not describe a point on P-256.
  static Future<EncryptionKeyPair> importPublicKeySec1Hex(
      EncryptionPublicKeyHex sec1Hex) async {
    return importPublicKeyRaw(Sec1PublicKey.decodeHex(sec1Hex.value));
  }

  /// Import a public-only EncryptionKeyPair from SEC1 uncompressed bytes.
  ///
  /// [raw] must be exactly 65 bytes: the `04` tag followed by the 32-byte x
  /// and 32-byte y coordinates. This is the inverse of [exportPublicKeyRaw].
  ///
  /// Throws [FormatException] if the length or tag is wrong, or if the bytes
  /// do not describe a point on P-256.
  static Future<EncryptionKeyPair> importPublicKeyRaw(Uint8List raw) async {
    final EcdhPublicKey publicKey = await EcdhPublicKey.importRawKey(
      Sec1PublicKey.validateRaw(raw), EllipticCurve.p256);

    return EncryptionKeyPair.publicOnly(publicKey: publicKey);
  }

  @override
  EcdhPrivateKey? get privateKey => _privateKey;

  @override
  EcdhPublicKey get publicKey => _publicKey;

  @override
  bool get hasPrivateKey => _privateKey != null;

  @override
  Future<ExportedJwk> exportPrivateKey() async {
    if (_privateKey == null) {
      throw StateError('Cannot export private key: This is a public-only key pair');
    }
    
    final Map<String, dynamic> jwkMap = await _privateKey.exportJsonWebKey();
    final String keyId = await calculateKeyId();
    
    return ExportedJwk(
      keyData: jwkMap,
      keyId: keyId,
      alg: JwkAlgorithm.ecdhEs256,
      use: JwkUse.encryption,
    );
  }

  @override
  Future<ExportedJwk> exportPublicKey() async {
    final Map<String, dynamic> jwkMap = await _publicKey.exportJsonWebKey();
    final String keyId = await calculateKeyId();
    
    return ExportedJwk(
      keyData: jwkMap,
      keyId: keyId,
      alg: JwkAlgorithm.ecdhEs256,
      use: JwkUse.encryption,
    );
  }

  @override
  Future<Uint8List> exportPublicKeyRaw() async {
    return Sec1PublicKey.validateRaw(await _publicKey.exportRawKey());
  }

  /// Export the public key as SEC1 uncompressed hex, typed as an encryption key.
  ///
  /// Narrows [IKeyPair.exportPublicKeySec1Hex] from `String` to
  /// [EncryptionPublicKeyHex]. Same 130 characters either way — the difference
  /// is that the result cannot be assigned to a variable or parameter
  /// expecting a signing key.
  @override
  Future<EncryptionPublicKeyHex> exportPublicKeySec1Hex() async {
    return EncryptionPublicKeyHex(
      Sec1PublicKey.encodeHex(await exportPublicKeyRaw()));
  }

  @override
  Future<String> calculateKeyId() async {
    // Simply return the standard RFC 7638 thumbprint.
    // The 'use' field (sig/enc) already distinguishes the key type.
    final Map<String, dynamic> publicJwkMap = await _publicKey.exportJsonWebKey();
    return calculateJwkThumbprint(publicJwkMap);
  }
}