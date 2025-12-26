/// Type-safe wrapper for RSA-OAEP encryption key pairs.
library;

import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';
import 'interfaces.dart';
import 'exported_jwk.dart';
import 'constants.dart';
import 'jwk_thumbprint.dart';

/// Type-safe wrapper for RSA-OAEP encryption key pairs.
/// 
/// Provides compile-time safety by restricting operations to encryption keys only.
/// Hardcodes algorithm as "RSA-OAEP-256" and use as "enc" to prevent misuse.
class EncryptionKeyPair implements IKeyPair<RsaOaepPrivateKey, RsaOaepPublicKey> {
  final RsaOaepPrivateKey? _privateKey;
  final RsaOaepPublicKey _publicKey;
  
  /// Creates a new EncryptionKeyPair wrapper with both private and public keys.
  /// 
  /// **IMPORTANT**: The caller must ensure that [privateKey] and [publicKey] 
  /// are mathematically paired (i.e., they belong to the same RSA key pair).
  /// This constructor does not validate the key pair relationship due to 
  /// WebCrypto API limitations. Mismatched keys will result in cryptographic
  /// failures during encryption/decryption operations.
  /// 
  /// Use [KeyDuoGenerator] to safely generate matched key pairs.
  /// 
  /// [privateKey] - The RSA-OAEP private key
  /// [publicKey] - The RSA-OAEP public key  
  EncryptionKeyPair({
    required RsaOaepPrivateKey privateKey,
    required RsaOaepPublicKey publicKey,
  }) : _privateKey = privateKey,
       _publicKey = publicKey;

  /// Creates a new public-only EncryptionKeyPair wrapper.
  /// 
  /// [publicKey] - The RSA-OAEP public key  
  EncryptionKeyPair.publicOnly({
    required RsaOaepPublicKey publicKey,
  }) : _privateKey = null,
       _publicKey = publicKey;

  @override
  RsaOaepPrivateKey? get privateKey => _privateKey;

  @override
  RsaOaepPublicKey get publicKey => _publicKey;

  @override
  bool get hasPrivateKey => _privateKey != null;

  @override
  Future<ExportedJwk> exportPrivateKey() async {
    if (_privateKey == null) {
      throw StateError('Cannot export private key: This is a public-only key pair');
    }
    
    final Map<String, dynamic> jwkMap = await _privateKey!.exportJsonWebKey();
    final String keyId = await calculateKeyId();
    
    return ExportedJwk(
      keyData: jwkMap,
      keyId: keyId,
      alg: JwkAlgorithm.rsaOaep256,
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
      alg: JwkAlgorithm.rsaOaep256,
      use: JwkUse.encryption,
    );
  }

  @override
  Future<String> calculateKeyId() async {
    // Simply return the standard RFC 7638 thumbprint.
    // The 'use' field (sig/enc) already distinguishes the key type.
    final Map<String, dynamic> publicJwkMap = await _publicKey.exportJsonWebKey();
    return calculateJwkThumbprint(publicJwkMap);
  }

  @override
  Future<bool> verifyKeyPair() async {
    if (_privateKey == null) {
      throw StateError('Cannot verify: public-only key pair');
    }
    
    try {
      final Uint8List testMessage = Uint8List.fromList('test'.codeUnits);
      final Uint8List encrypted = await _publicKey.encryptBytes(testMessage);
      final Uint8List decrypted = await _privateKey!.decryptBytes(encrypted);
      
      if (testMessage.length != decrypted.length) return false;
      for (int i = 0; i < testMessage.length; i++) {
        if (testMessage[i] != decrypted[i]) return false;
      }
      
      return true;
    } catch (e) {
      return false;
    }
  }
}