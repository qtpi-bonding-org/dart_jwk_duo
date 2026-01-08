/// Service for generating new cryptographic keys.
library;

import 'package:webcrypto/webcrypto.dart';
import 'key_duo.dart';
import 'signing_key_pair.dart';
import 'encryption_key_pair.dart';
import 'symmetric_key.dart';
import 'constants.dart';

/// Service for generating new cryptographic keys
/// 
/// Provides static methods for creating new KeyDuo and SymmetricKey instances
/// with proper cryptographic parameters.
class GenerationService {
  /// Generate new KeyDuo (ECDSA P-256 + RSA-OAEP)
  /// 
  /// Creates a new KeyDuo containing both signing and encryption key pairs:
  /// - Signing: ECDSA P-256 for digital signatures and identity
  /// - Encryption: RSA-OAEP-256 for data encryption and key wrapping
  /// 
  /// [modulusLength] - RSA modulus length in bits. Defaults to 3072 for enhanced security.
  /// 
  /// Returns a new [KeyDuo] with both private and public keys.
  static Future<KeyDuo> generateKeyDuo({int modulusLength = RsaParameters.modulusLength3072}) async {
    // Generate ECDSA P-256 key pair for signing
    final ({EcdsaPrivateKey privateKey, EcdsaPublicKey publicKey}) signingKeyPair = 
        await EcdsaPrivateKey.generateKey(EllipticCurve.p256);
    
    // Generate RSA-OAEP key pair for encryption  
    final ({RsaOaepPrivateKey privateKey, RsaOaepPublicKey publicKey}) encryptionKeyPair = 
        await RsaOaepPrivateKey.generateKey(
          modulusLength,
          BigInt.from(RsaParameters.publicExponent),
          Hash.sha256,
        );
    
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