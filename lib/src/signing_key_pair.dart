/// Type-safe wrapper for RSA-PSS signing key pairs.
library;

import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';
import 'interfaces.dart';
import 'exported_jwk.dart';
import 'constants.dart';
import 'jwk_thumbprint.dart';

/// Type-safe wrapper for RSA-PSS signing key pairs.
/// 
/// Provides compile-time safety by restricting operations to signing keys only.
/// Hardcodes algorithm as "PS256" and use as "sig" to prevent misuse.
class SigningKeyPair implements IKeyPair<RsaPssPrivateKey, RsaPssPublicKey> {
  final RsaPssPrivateKey? _privateKey;
  final RsaPssPublicKey _publicKey;
  
  /// Creates a new SigningKeyPair wrapper with both private and public keys.
  /// 
  /// **IMPORTANT**: The caller must ensure that [privateKey] and [publicKey] 
  /// are mathematically paired (i.e., they belong to the same RSA key pair).
  /// This constructor does not validate the key pair relationship due to 
  /// WebCrypto API limitations. Mismatched keys will result in cryptographic
  /// failures during signing/verification operations.
  /// 
  /// Use [KeyDuoGenerator] to safely generate matched key pairs.
  /// 
  /// [privateKey] - The RSA-PSS private key
  /// [publicKey] - The RSA-PSS public key  
  SigningKeyPair({
    required RsaPssPrivateKey privateKey,
    required RsaPssPublicKey publicKey,
  }) : _privateKey = privateKey,
       _publicKey = publicKey;

  /// Creates a new public-only SigningKeyPair wrapper.
  /// 
  /// [publicKey] - The RSA-PSS public key  
  SigningKeyPair.publicOnly({
    required RsaPssPublicKey publicKey,
  }) : _privateKey = null,
       _publicKey = publicKey;

  @override
  RsaPssPrivateKey? get privateKey => _privateKey;

  @override
  RsaPssPublicKey get publicKey => _publicKey;

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
      alg: JwkAlgorithm.ps256,
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
      alg: JwkAlgorithm.ps256,
      use: JwkUse.signature,
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
  Future<bool> validateKeyPair() async {
    if (_privateKey == null) {
      throw StateError('Cannot validate key pair: This is a public-only key pair');
    }
    
    try {
      // Test message for validation
      final testMessage = Uint8List.fromList('dart-jwk-duo-validation-test'.codeUnits);
      
      // Sign with private key using standard salt length (32 bytes for SHA-256)
      final signature = await _privateKey!.signBytes(testMessage, 32);
      final isValid = await _publicKey.verifyBytes(signature, testMessage, 32);
      
      return isValid;
    } catch (e) {
      // Any crypto exception indicates mismatched keys
      return false;
    }
  }
}