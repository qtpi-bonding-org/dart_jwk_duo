/// Service for generating new cryptographic keys.
library;

import 'package:webcrypto/webcrypto.dart';
import 'key_duo.dart';
import 'signing_key_pair.dart';
import 'encryption_key_pair.dart';
import 'symmetric_key.dart';

/// Service for generating new cryptographic keys
/// 
/// Provides static methods for creating new KeyDuo and SymmetricKey instances
/// with proper cryptographic parameters.
class GenerationService {
  /// Generate new KeyDuo (ECDSA P-256 + ECDH P-256)
  /// 
  /// Creates a new KeyDuo containing both signing and encryption key pairs:
  /// - Signing: ECDSA P-256 for digital signatures and identity
  /// - Encryption: ECDH P-256 for key agreement and hybrid encryption
  /// 
  /// Returns a new [KeyDuo] with both private and public keys.
  static Future<KeyDuo> generateKeyDuo() async {
    print('🔍 GenerationService - Starting key generation...');
    
    // Generate ECDSA P-256 key pair for signing
    // WebCrypto browser compatibility: explicitly specify key usages
    print('🔍 GenerationService - Generating ECDSA P-256 signing key...');
    final ({EcdsaPrivateKey privateKey, EcdsaPublicKey publicKey}) signingKeyPair;
    try {
      signingKeyPair = await EcdsaPrivateKey.generateKey(EllipticCurve.p256);
      print('🔍 GenerationService - ECDSA key generated successfully');
    } catch (e) {
      print('❌ GenerationService - ECDSA key generation failed: $e');
      rethrow;
    }
    
    // Generate ECDH P-256 key pair for encryption  
    // WebCrypto browser compatibility: ECDH keys may have stricter usage validation
    print('🔍 GenerationService - Generating ECDH P-256 encryption key...');
    final ({EcdhPrivateKey privateKey, EcdhPublicKey publicKey}) encryptionKeyPair;
    try {
      encryptionKeyPair = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
      print('🔍 GenerationService - ECDH key generated successfully');
    } catch (e) {
      print('❌ GenerationService - ECDH key generation failed: $e');
      print('❌ GenerationService - This may be a WebCrypto browser compatibility issue');
      print('❌ GenerationService - Error details: ${e.runtimeType} - $e');
      rethrow;
    }
    
    // Create typed wrappers
    final SigningKeyPair signing = SigningKeyPair(
      privateKey: signingKeyPair.privateKey,
      publicKey: signingKeyPair.publicKey,
    );
    
    final EncryptionKeyPair encryption = EncryptionKeyPair(
      privateKey: encryptionKeyPair.privateKey,
      publicKey: encryptionKeyPair.publicKey,
    );
    
    return KeyDuo(
      signing: signing,
      encryption: encryption,
    );
  }
  
  /// Generate new symmetric key (AES-256-GCM)
  /// 
  /// Creates a new SymmetricKey for data encryption using AES-256-GCM.
  /// This is used for encrypting actual user data in the E2EE system.
  /// 
  /// Returns a new [SymmetricKey] ready for encryption operations.
  static Future<SymmetricKey> generateSymmetricKey() async {
    final AesGcmSecretKey aesKey = await AesGcmSecretKey.generateKey(256);
    return SymmetricKey.fromAesKey(aesKey);
  }
}