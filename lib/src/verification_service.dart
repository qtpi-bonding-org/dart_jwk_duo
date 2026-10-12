/// Service for cryptographic verification (roundtrip tests).
library;

import 'dart:typed_data';
import 'bridge/api.dart' as r;
import 'encryption_key_pair.dart';
import 'errors.dart';
import 'init.dart';
import 'key_duo.dart';
import 'key_duo_serializer.dart';
import 'public_key_hex.dart';
import 'signing_key_pair.dart';
import 'symmetric_key.dart';

/// Service for cryptographic verification (roundtrip tests).
class VerificationService {
  /// Verify a signature given only the signer's SEC1 public key hex.
  ///
  /// Throws [FormatException] if the hex is not a valid P-256 point.
  static Future<bool> verifySignatureWithPublicKeySec1Hex({
    required SigningPublicKeyHex publicKeySec1Hex,
    required Uint8List signature,
    required Uint8List data,
  }) async {
    final SigningKeyPair keyPair =
        await SigningKeyPair.importPublicKeySec1Hex(publicKeySec1Hex);
    try {
      return await keyPair.verifyBytes(signature, data);
    } finally {
      keyPair.dispose();
    }
  }

  /// Verify both halves of a KeyDuo by cryptographic roundtrip.
  ///
  /// Throws [StateError] if either half is public-only.
  static Future<bool> verifyKeyDuo(KeyDuo keyDuo) async {
    final bool signingOk = await verifySigningKeyPair(keyDuo.signingKeyPair);
    if (!signingOk) return false;
    return await verifyEncryptionKeyPair(keyDuo.encryptionKeyPair);
  }

  /// Sign/verify roundtrip. Throws [StateError] on a public-only key pair.
  static Future<bool> verifySigningKeyPair(SigningKeyPair keyPair) async {
    await ensureInitialized();
    return rethrowAsDart(() => r.verifySigningKeyPair(kp: keyPair.handle));
  }

  /// Encrypt/decrypt roundtrip. Throws [StateError] on a public-only key pair.
  static Future<bool> verifyEncryptionKeyPair(EncryptionKeyPair keyPair) async {
    await ensureInitialized();
    return rethrowAsDart(() => r.verifyEncryptionKeyPair(kp: keyPair.handle));
  }

  /// Encrypt/decrypt roundtrip with a symmetric key.
  static Future<bool> verifySymmetricKey(SymmetricKey symmetricKey) async {
    await ensureInitialized();
    return rethrowAsDart(() => r.verifySymmetricKey(k: symmetricKey.handle));
  }

  /// Imports a private JWK Set and verifies it by cryptographic roundtrip.
  ///
  /// Throws [FormatException] if the set is invalid and [StateError] if the
  /// roundtrip fails.
  static Future<KeyDuo> verifyKeyDuoJwk(String jwkSetJson) async {
    const KeyDuoSerializer serializer = KeyDuoSerializer();
    final KeyDuo keyDuo = await serializer.importKeyDuoJwk(jwkSetJson);

    final bool verified = await verifyKeyDuo(keyDuo);
    if (!verified) {
      keyDuo.dispose();
      throw StateError('Key verification failed: cryptographic roundtrip test failed');
    }

    return keyDuo;
  }
}
