/// Key duo generation functionality.
library;

import 'package:webcrypto/webcrypto.dart';
import 'key_duo.dart';
import 'signing_key_pair.dart';
import 'encryption_key_pair.dart';
import 'constants.dart';

/// Interface for generating key duos.
/// 
/// Provides a contract for creating new key pairs with proper parameters.
abstract class IKeyDuoGenerator {
  /// Generates a new key duo containing both signing and encryption key pairs.
  /// 
  /// Returns a [KeyDuo] with ECDSA P-256 signing keys and RSA-OAEP-256 encryption keys.
  Future<KeyDuo> generateKeyDuo();
}

/// Generator for creating key duos with proper parameters.
/// 
/// Creates both signing (ECDSA P-256) and encryption (RSA-OAEP-256) key pairs.
class KeyDuoGenerator implements IKeyDuoGenerator {
  final int _modulusLength;

  /// Creates a new KeyDuoGenerator.
  /// 
  /// [modulusLength] - RSA modulus length in bits for encryption key. 
  ///                   Defaults to 3072 for enhanced security.
  const KeyDuoGenerator({
    int modulusLength = RsaParameters.modulusLength3072,
  }) : _modulusLength = modulusLength;

  @override
  Future<KeyDuo> generateKeyDuo() async {
    // Generate ECDSA P-256 key pair for signing
    final ({EcdsaPrivateKey privateKey, EcdsaPublicKey publicKey}) signingKeyPair = 
        await EcdsaPrivateKey.generateKey(EllipticCurve.p256);
    
    // Generate RSA-OAEP key pair for encryption  
    final ({RsaOaepPrivateKey privateKey, RsaOaepPublicKey publicKey}) encryptionKeyPair = 
        await RsaOaepPrivateKey.generateKey(
          _modulusLength,
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
}