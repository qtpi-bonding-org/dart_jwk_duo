/// Type-safe wrapper for ECDSA P-256 signing key pairs.
library;

import 'dart:convert';
import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';
import 'interfaces.dart';
import 'exported_jwk.dart';
import 'constants.dart';

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

  /// Export public key as raw bytes (65 bytes: 04 prefix + x + y).
  Future<Uint8List> exportPublicKeyRaw() async {
    return await _publicKey.exportRawKey();
  }

  /// Export public key as hex string (128 chars, no 04 prefix) for auth token.
  Future<String> exportPublicKeyHex() async {
    final Uint8List raw = await exportPublicKeyRaw();
    // Raw key is 65 bytes (04 prefix + 32 bytes x + 32 bytes y)
    // Skip the 04 prefix to get 64 bytes = 128 hex chars
    final Uint8List bytes = raw.length == 65 ? raw.sublist(1) : raw;
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // IKeyPair Implementation
  // ═══════════════════════════════════════════════════════════════════════════

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
    // RFC 7638 thumbprint for EC keys: {"crv":"...","kty":"EC","x":"...","y":"..."}
    final Map<String, dynamic> jwk = await _publicKey.exportJsonWebKey();
    final String canonical = '{"crv":"${jwk['crv']}","kty":"${jwk['kty']}","x":"${jwk['x']}","y":"${jwk['y']}"}';
    final Uint8List hash = await Hash.sha256.digestBytes(utf8.encode(canonical));
    return base64Url.encode(hash).replaceAll('=', '');
  }

  @override
  Future<bool> validateKeyPair() async {
    if (_privateKey == null) {
      throw StateError('Cannot validate: public-only key pair');
    }
    
    try {
      final Uint8List testMessage = Uint8List.fromList('dart-jwk-duo-validation'.codeUnits);
      final Uint8List signature = await signBytes(testMessage);
      return await verifyBytes(signature, testMessage);
    } catch (e) {
      return false;
    }
  }
}
