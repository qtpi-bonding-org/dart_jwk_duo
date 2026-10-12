/// Container for both signing and encryption key pairs.
library;

import 'dart:convert';
import 'dart:typed_data';
import 'constants.dart';
import 'interfaces.dart';
import 'signing_key_pair.dart';
import 'encryption_key_pair.dart';
import 'crypto_service.dart';
import 'hex_codec.dart';
import 'public_key_hex.dart';

/// Container holding both signing and encryption key pairs.
/// 
/// Provides type-safe access to both key pairs with compile-time guarantees
/// about the key types and their intended uses.
class KeyDuo implements IKeyDuo {

  /// Creates a new KeyDuo container.
  /// 
  /// [signing] - The signing key pair (ECDSA P-256)
  /// [encryption] - The encryption key pair (HPKE P-256)
  ///
  /// Throws [ArgumentError] if both halves have the same public key.
  KeyDuo({
    required SigningKeyPair signing,
    required EncryptionKeyPair encryption,
  }) : _signing = signing,
       _encryption = encryption {
    if (_sameBytes(signingPublicRawOf(_signing), encryptionPublicRawOf(_encryption))) {
      throw ArgumentError(
        'Signing and encryption public keys are identical. One key has been '
        'placed in both fields; they must come from different key pairs.',
      );
    }
  }
  final SigningKeyPair _signing;
  final EncryptionKeyPair _encryption;

  @override
  IKeyPair get signing => _signing;

  @override
  IKeyPair get encryption => _encryption;
  
  /// Access the concrete SigningKeyPair for signing operations.
  SigningKeyPair get signingKeyPair => _signing;
  
  /// Access the concrete EncryptionKeyPair for encryption operations.
  EncryptionKeyPair get encryptionKeyPair => _encryption;

  /// Export both public keys as a typed [PublicKeyDuo].
  ///
  /// Prefer this over exporting the two hex strings separately: the slots are
  /// typed, so the pair cannot be assembled with the arguments transposed or
  /// with the same key in both fields.
  Future<PublicKeyDuo> exportPublicKeyDuo() async {
    return PublicKeyDuo(
      signing: await _signing.exportPublicKeySec1Hex(),
      encryption: await _encryption.exportPublicKeySec1Hex(),
    );
  }

  /// Encrypt data to this KeyDuo's own encryption key
  ///
  /// Convenience method that delegates to CryptoService.encrypt().
  /// To encrypt to someone else, call CryptoService.encrypt() with their
  /// [EncryptionKeyPair] directly — a whole KeyDuo is not required.
  ///
  /// [data] - The data to encrypt
  /// [info] - Optional HPKE context info; decryption must pass the same value
  /// [aad] - Optional associated data; decryption must pass the same value
  ///
  /// Returns encrypted bytes.
  Future<Uint8List> encrypt(Uint8List data, {Uint8List? info, Uint8List? aad}) async {
    return await CryptoService.encrypt(data, _encryption, info: info, aad: aad);
  }

  /// Decrypt data with this KeyDuo's encryption key
  ///
  /// Convenience method that delegates to CryptoService.decrypt().
  ///
  /// [data] - The encrypted data to decrypt
  ///
  /// Returns decrypted bytes.
  /// Throws [StateError] if KeyDuo has no private key.
  Future<Uint8List> decrypt(Uint8List data, {Uint8List? info, Uint8List? aad}) async {
    return await CryptoService.decrypt(data, _encryption, info: info, aad: aad);
  }

  /// Sign data with this KeyDuo's signing key
  /// 
  /// Convenience method that delegates to SigningKeyPair.signBytes().
  /// 
  /// [data] - The data to sign
  /// 
  /// Returns signature bytes.
  Future<Uint8List> sign(Uint8List data) async {
    return await _signing.signBytes(data);
  }
  
  /// Verify signature with this KeyDuo's signing key
  /// 
  /// Convenience method that delegates to SigningKeyPair.verifyBytes().
  /// 
  /// [data] - The original data
  /// [signature] - The signature to verify
  /// 
  /// Returns `true` if signature is valid, `false` otherwise.
  Future<bool> verifySignature(Uint8List data, Uint8List signature) async {
    return await _signing.verifyBytes(signature, data);
  }
  
  /// Encrypt string, return base64
  /// 
  /// Convenience method for string encryption.
  /// 
  /// [data] - The string to encrypt
  /// 
  /// Returns base64-encoded encrypted data.
  Future<String> encryptString(String data, {Uint8List? info, Uint8List? aad}) async {
    return await CryptoService.encryptString(data, _encryption, info: info, aad: aad);
  }
  
  /// Decrypt base64 string
  /// 
  /// Convenience method for string decryption.
  /// 
  /// [base64Data] - Base64-encoded encrypted data
  /// 
  /// Returns decrypted string. Throws [FormatException] unless [base64Data] is padded standard base64.
  Future<String> decryptString(String base64Data, {Uint8List? info, Uint8List? aad}) async {
    return await CryptoService.decryptString(base64Data, _encryption, info: info, aad: aad);
  }
  
  /// Sign string, return hex signature
  /// 
  /// Convenience method for string signing.
  /// 
  /// [data] - The string to sign
  /// 
  /// Returns hex-encoded signature.
  Future<String> signString(String data) async {
    final Uint8List dataBytes = utf8.encode(data);
    return HexCodec.encode(await sign(dataBytes));
  }
  
  /// Verify hex signature
  /// 
  /// Convenience method for string signature verification.
  /// 
  /// [data] - The original string
  /// [signatureHex] - Hex-encoded signature
  /// 
  /// Returns `true` if signature is valid, `false` otherwise.
  Future<bool> verifySignatureString(String data, String signatureHex) async {
    final Uint8List signatureBytes = HexCodec.decode(
      signatureHex,
      expectedLength: CryptoSizes.ecdsaP256SignatureLength * 2,
    );
    final Uint8List dataBytes = utf8.encode(data);
    return await verifySignature(dataBytes, signatureBytes);
  }

  /// Releases the native handles of both key pairs.
  void dispose() {
    _signing.dispose();
    _encryption.dispose();
  }
}

bool _sameBytes(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
