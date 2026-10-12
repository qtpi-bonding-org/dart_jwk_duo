/// Cryptographic operations: HPKE encryption, AES-256-GCM, ECDSA signing.
library;

import 'dart:convert';
import 'dart:typed_data';
import 'bridge/api.dart' as r;
import 'constants.dart';
import 'encryption_key_pair.dart';
import 'errors.dart';
import 'hex_codec.dart';
import 'init.dart';
import 'signing_key_pair.dart';
import 'symmetric_key.dart';

/// Static cryptographic operations. All primitives run in rust_jwk_duo.
class CryptoService {
  // ═══════════════════════════════════════════════════════════════════════════
  // Asymmetric Operations - HPKE (RFC 9180), single shot, base mode
  // ═══════════════════════════════════════════════════════════════════════════

  /// Encrypts [data] to [recipient]'s public key.
  ///
  /// The blob is `0x01 || enc(65) || ciphertext || tag`. [info] and [aad] are
  /// bound into the encryption: decryption must pass the same values.
  static Future<Uint8List> encrypt(
    Uint8List data,
    EncryptionKeyPair recipient, {
    Uint8List? info,
    Uint8List? aad,
  }) async {
    await ensureInitialized();
    return Uint8List.fromList(rethrowAsDart(() => r.hpkeEncrypt(
          data: data,
          recipient: encryptionHandleOf(recipient),
          info: info ?? Uint8List(0),
          aad: aad ?? Uint8List(0),
        )));
  }

  /// Decrypts a blob produced by [encrypt].
  ///
  /// Throws [StateError] if [recipient] is public-only, and
  /// [FormatException] if [data] is malformed or authentication fails (wrong
  /// key, [info] or [aad], or tampered data).
  static Future<Uint8List> decrypt(
    Uint8List data,
    EncryptionKeyPair recipient, {
    Uint8List? info,
    Uint8List? aad,
  }) async {
    await ensureInitialized();
    return Uint8List.fromList(rethrowAsDart(() => r.hpkeDecrypt(
          data: data,
          recipient: encryptionHandleOf(recipient),
          info: info ?? Uint8List(0),
          aad: aad ?? Uint8List(0),
        )));
  }

  /// Signs [data] with [signer]. Returns a 64-byte P1363 signature.
  static Future<Uint8List> sign(Uint8List data, SigningKeyPair signer) async {
    return await signer.signBytes(data);
  }

  /// Verifies [signature] over [data]; `false` if it does not verify.
  static Future<bool> verifySignature(
      Uint8List data, Uint8List signature, SigningKeyPair verifier) async {
    return await verifier.verifyBytes(signature, data);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Symmetric Operations (SymmetricKey-based)
  // ═══════════════════════════════════════════════════════════════════════════

  /// Encrypts [data] with AES-256-GCM, optionally binding [aad].
  static Future<Uint8List> encryptSymmetric(
      Uint8List data, SymmetricKey symmetricKey, {Uint8List? aad}) async {
    await ensureInitialized();
    return Uint8List.fromList(rethrowAsDart(() => r.symmetricEncrypt(
        data: data, k: symmetricHandleOf(symmetricKey), aad: aad ?? Uint8List(0))));
  }

  /// Decrypts a blob produced by [encryptSymmetric].
  ///
  /// Throws [FormatException] if [data] is malformed or authentication fails
  /// (wrong key or [aad], or tampered data).
  static Future<Uint8List> decryptSymmetric(
      Uint8List data, SymmetricKey symmetricKey, {Uint8List? aad}) async {
    await ensureInitialized();
    return Uint8List.fromList(rethrowAsDart(() => r.symmetricDecrypt(
        data: data, k: symmetricHandleOf(symmetricKey), aad: aad ?? Uint8List(0))));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Convenience Methods (String-based)
  // ═══════════════════════════════════════════════════════════════════════════

  /// Encrypts a UTF-8 string to [recipient]; returns base64.
  static Future<String> encryptString(
    String data,
    EncryptionKeyPair recipient, {
    Uint8List? info,
    Uint8List? aad,
  }) async {
    await ensureInitialized();
    return rethrowAsDart(() => r.hpkeEncryptString(
          data: data,
          recipient: encryptionHandleOf(recipient),
          info: info ?? Uint8List(0),
          aad: aad ?? Uint8List(0),
        ));
  }

  /// Decrypts base64 produced by [encryptString] back to a string.
  ///
  /// Throws as [decrypt] does; also [FormatException] for anything but padded
  /// standard base64 (URL-safe alphabet and missing padding are rejected) or
  /// non-UTF-8 plaintext.
  static Future<String> decryptString(
    String base64Data,
    EncryptionKeyPair recipient, {
    Uint8List? info,
    Uint8List? aad,
  }) async {
    await ensureInitialized();
    return rethrowAsDart(() => r.hpkeDecryptString(
          b64: base64Data,
          recipient: encryptionHandleOf(recipient),
          info: info ?? Uint8List(0),
          aad: aad ?? Uint8List(0),
        ));
  }

  /// Signs a UTF-8 string; returns the signature as hex.
  static Future<String> signString(String data, SigningKeyPair signer) async {
    return HexCodec.encode(await sign(utf8.encode(data), signer));
  }

  /// Verifies a hex signature over a UTF-8 string.
  static Future<bool> verifySignatureString(
      String data, String signatureHex, SigningKeyPair verifier) async {
    final Uint8List signatureBytes = HexCodec.decode(
      signatureHex,
      expectedLength: CryptoSizes.ecdsaP256SignatureLength * 2,
    );
    return await verifySignature(utf8.encode(data), signatureBytes, verifier);
  }
}
