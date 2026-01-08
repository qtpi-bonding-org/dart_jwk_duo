/// Type-safe wrapper for RSA-OAEP encryption key pairs.
library;

import 'package:webcrypto/webcrypto.dart';
import 'interfaces.dart';
import 'exported_jwk.dart';
import 'constants.dart';
import 'jwk_thumbprint.dart';

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
    
    final Map<String, dynamic> jwkMap = await _privateKey!.exportJsonWebKey();
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
  Future<String> calculateKeyId() async {
    // Simply return the standard RFC 7638 thumbprint.
    // The 'use' field (sig/enc) already distinguishes the key type.
    final Map<String, dynamic> publicJwkMap = await _publicKey.exportJsonWebKey();
    return calculateJwkThumbprint(publicJwkMap);
  }
}