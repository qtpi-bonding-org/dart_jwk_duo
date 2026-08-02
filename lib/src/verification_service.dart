/// Service for cryptographic verification (roundtrip tests).
library;

import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';
import 'constants.dart';
import 'key_duo.dart';
import 'signing_key_pair.dart';
import 'encryption_key_pair.dart';
import 'symmetric_key.dart';
import 'crypto_service.dart';
import 'key_duo_serializer.dart';
import 'public_key_hex.dart';

/// Service for cryptographic verification (roundtrip tests)
/// 
/// Performs actual cryptographic operations to verify that keys work correctly.
/// Use ValidationService for structural checks before verification.
class VerificationService {
  /// Verify a signature using only a SEC1 public key hex string.
  ///
  /// Imports the public key from hex and verifies the signature in one call.
  ///
  /// Parameters:
  /// - [publicKeySec1Hex]: SEC1 hex of the ECDSA P-256 **signing** public key.
  ///   Typed as [SigningPublicKeyHex] so an encryption key cannot be passed
  ///   here — the bytes alone could not tell them apart, and the mistake would
  ///   surface only as a silent verification failure.
  /// - [signature]: The signature bytes to verify
  /// - [data]: The original data that was signed
  ///
  /// Returns `true` if the signature is valid, `false` otherwise.
  ///
  /// Throws [FormatException] if [publicKeySec1Hex] is not a valid SEC1
  /// P-256 point. A malformed key is a caller error and is reported as one
  /// rather than being folded into a `false` result.
  static Future<bool> verifySignatureWithPublicKeySec1Hex({
    required SigningPublicKeyHex publicKeySec1Hex,
    required Uint8List signature,
    required Uint8List data,
  }) async {
    final SigningKeyPair keyPair =
        await SigningKeyPair.importPublicKeySec1Hex(publicKeySec1Hex);
    return await keyPair.verifyBytes(signature, data);
  }

  /// Verify KeyDuo works via crypto roundtrips
  /// 
  /// Tests both signing and encryption key pairs with actual crypto operations.
  /// 
  /// [keyDuo] - The KeyDuo to verify
  /// 
  /// Returns `true` if both key pairs pass verification, `false` otherwise.
  /// Throws [StateError] if KeyDuo has no private keys.
  static Future<bool> verifyKeyDuo(KeyDuo keyDuo) async {
    final bool signingOk = await verifySigningKeyPair(keyDuo.signingKeyPair);
    if (!signingOk) return false;
    
    final bool encryptionOk = await verifyEncryptionKeyPair(keyDuo.encryptionKeyPair);
    return encryptionOk;
  }

  /// Verify signing key pair works via sign/verify roundtrip
  /// 
  /// Signs a test message with private key and verifies with public key.
  /// 
  /// [keyPair] - The SigningKeyPair to verify
  /// 
  /// Returns `true` if sign/verify roundtrip succeeds, `false` otherwise.
  /// Throws [StateError] if key pair has no private key.
  static Future<bool> verifySigningKeyPair(SigningKeyPair keyPair) async {
    if (!keyPair.hasPrivateKey) {
      throw StateError('Cannot verify: public-only key pair');
    }
    
    try {
      final Uint8List testMessage = Uint8List.fromList('dart-jwk-duo-verify'.codeUnits);
      final Uint8List signature = await keyPair.signBytes(testMessage);
      return await keyPair.verifyBytes(signature, testMessage);
    } catch (e) {
      return false;
    }
  }

  /// Verify encryption key pair works via full encrypt/decrypt roundtrip
  ///
  /// Tests the complete ECDH + HKDF + AES-GCM pipeline by running
  /// CryptoService.encrypt → CryptoService.decrypt, ensuring the entire
  /// derivation and encryption path works end-to-end.
  ///
  /// [keyPair] - The EncryptionKeyPair to verify
  ///
  /// Returns `true` if encrypt/decrypt roundtrip succeeds, `false` otherwise.
  /// Throws [StateError] if key pair has no private key.
  static Future<bool> verifyEncryptionKeyPair(EncryptionKeyPair keyPair) async {
    if (!keyPair.hasPrivateKey) {
      throw StateError('Cannot verify: public-only key pair');
    }

    try {
      final Uint8List testMessage = Uint8List.fromList('dart-jwk-duo-verify-enc'.codeUnits);

      // Run the full CryptoService encrypt/decrypt roundtrip
      final Uint8List encrypted = await CryptoService.encrypt(testMessage, keyPair);
      final Uint8List decrypted = await CryptoService.decrypt(encrypted, keyPair);

      if (testMessage.length != decrypted.length) return false;
      for (int i = 0; i < testMessage.length; i++) {
        if (testMessage[i] != decrypted[i]) return false;
      }
      return true;
    } catch (e) {
      return false;
    }
  }

  /// Verify symmetric key works via encrypt/decrypt roundtrip
  /// 
  /// Encrypts test data with the key and decrypts to verify it works.
  /// 
  /// [symmetricKey] - The SymmetricKey to verify
  /// 
  /// Returns `true` if encrypt/decrypt roundtrip succeeds, `false` otherwise.
  static Future<bool> verifySymmetricKey(SymmetricKey symmetricKey) async {
    try {
      final Uint8List testData = Uint8List.fromList('verify-symmetric-key'.codeUnits);
      final Uint8List iv = Uint8List(CryptoSizes.aesGcmIvLength);
      fillRandomBytes(iv);
      final Uint8List encrypted = await symmetricKey.internal.encryptBytes(testData, iv);
      final Uint8List decrypted = await symmetricKey.internal.decryptBytes(encrypted, iv);
      
      if (testData.length != decrypted.length) return false;
      for (int i = 0; i < testData.length; i++) {
        if (testData[i] != decrypted[i]) return false;
      }
      return true;
    } catch (e) {
      return false;
    }
  }

  /// Import and verify KeyDuo JWK (combines import + verification)
  /// 
  /// Imports a KeyDuo from JWK Set JSON and runs full cryptographic verification.
  /// This is a convenience method that combines serialization and verification.
  /// 
  /// [jwkSetJson] - JSON string containing KeyDuo JWK Set
  /// 
  /// Returns the verified [KeyDuo] on success.
  /// Throws [FormatException] if JWK structure is invalid.
  /// Throws [StateError] if keys don't have private material or verification fails.
  static Future<KeyDuo> verifyKeyDuoJwk(String jwkSetJson) async {
    const KeyDuoSerializer serializer = KeyDuoSerializer();
    final KeyDuo keyDuo = await serializer.importKeyDuoJwk(jwkSetJson);
    
    final bool verified = await verifyKeyDuo(keyDuo);
    if (!verified) {
      throw StateError('Key verification failed: cryptographic roundtrip test failed');
    }
    
    return keyDuo;
  }
}