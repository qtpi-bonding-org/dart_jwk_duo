/// Container for both signing and encryption key pairs.
library;

import 'package:webcrypto/webcrypto.dart';
import 'interfaces.dart';
import 'signing_key_pair.dart';
import 'encryption_key_pair.dart';

/// Container holding both signing and encryption key pairs.
/// 
/// Provides type-safe access to both key pairs with compile-time guarantees
/// about the key types and their intended uses.
class KeyDuo implements IKeyDuo {
  final SigningKeyPair _signing;
  final EncryptionKeyPair _encryption;

  /// Creates a new KeyDuo container.
  /// 
  /// [signing] - The signing key pair (ECDSA P-256)
  /// [encryption] - The encryption key pair (RSA-OAEP-256)
  const KeyDuo({
    required SigningKeyPair signing,
    required EncryptionKeyPair encryption,
  }) : _signing = signing,
       _encryption = encryption;

  @override
  IKeyPair<EcdsaPrivateKey?, EcdsaPublicKey> get signing => _signing;

  @override
  IKeyPair<RsaOaepPrivateKey?, RsaOaepPublicKey> get encryption => _encryption;
  
  /// Access the concrete SigningKeyPair for signing operations.
  SigningKeyPair get signingKeyPair => _signing;
}