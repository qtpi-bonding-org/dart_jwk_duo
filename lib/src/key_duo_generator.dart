/// Key duo generation functionality.
library;

import 'package:webcrypto/webcrypto.dart';
import 'interfaces.dart';
import 'key_duo.dart';
import 'signing_key_pair.dart';
import 'encryption_key_pair.dart';
import 'constants.dart';

/// Interface for generating key duos.
/// 
/// Provides a contract for creating new key pairs with proper RSA parameters.
abstract class IKeyDuoGenerator {
  /// Generates a new key duo containing both signing and encryption key pairs.
  /// 
  /// Returns a [KeyDuo] with RSA-PSS-256 signing keys and RSA-OAEP-256 encryption keys.
  /// Uses 3072-bit modulus length (default), public exponent 65537, and SHA-256 hash algorithm.
  Future<IKeyDuo> generateKeyDuo();
}

/// Generator for creating key duos with proper RSA parameters.
/// 
/// Creates both signing (RSA-PSS-256) and encryption (RSA-OAEP-256) key pairs
/// using NIST recommended parameters: configurable modulus length (defaults to 2048-bit), 
/// 65537 public exponent, SHA-256 hash.
class KeyDuoGenerator implements IKeyDuoGenerator {
  static const Hash _hash = Hash.sha256;
  static final BigInt _publicExponent = BigInt.from(RsaParameters.publicExponent);
  
  final int _modulusLength;

  /// Creates a new KeyDuoGenerator.
  /// 
  /// [modulusLength] - RSA modulus length in bits. Defaults to 3072 for enhanced security.
  ///                   Use 2048 for compatibility, 4096 for maximum security.
  const KeyDuoGenerator({
    int modulusLength = RsaParameters.modulusLength3072,
  }) : _modulusLength = modulusLength;

  @override
  Future<IKeyDuo> generateKeyDuo() async {
    // Generate RSA-PSS key pair for signing
    final signingKeyPair = await RsaPssPrivateKey.generateKey(
      _modulusLength,
      _publicExponent,
      _hash,
    );
    
    // Generate RSA-OAEP key pair for encryption  
    final encryptionKeyPair = await RsaOaepPrivateKey.generateKey(
      _modulusLength,
      _publicExponent,
      _hash,
    );
    
    // Create typed wrappers
    final signing = SigningKeyPair(
      privateKey: signingKeyPair.privateKey,
      publicKey: signingKeyPair.publicKey,
    );
    
    final encryption = EncryptionKeyPair(
      privateKey: encryptionKeyPair.privateKey,
      publicKey: encryptionKeyPair.publicKey,
    );
    
    return KeyDuo(
      signing: signing,
      encryption: encryption,
    );
  }
}