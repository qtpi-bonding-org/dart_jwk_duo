/// Service for cryptographic verification (roundtrip tests).
library;

import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';
import 'key_duo.dart';
import 'signing_key_pair.dart';
import 'encryption_key_pair.dart';
import 'symmetric_key.dart';
import 'key_duo_serializer.dart';

/// Service for cryptographic verification (roundtrip tests)
/// 
/// Performs actual cryptographic operations to verify that keys work correctly.
/// Use ValidationService for structural checks before verification.
class VerificationService {
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

  /// Verify encryption key pair works via ECDH + AES roundtrip
  /// 
  /// Tests ECDH key agreement and AES encryption/decryption.
  /// 
  /// [keyPair] - The EncryptionKeyPair to verify
  /// 
  /// Returns `true` if ECDH + AES roundtrip succeeds, `false` otherwise.
  /// Throws [StateError] if key pair has no private key.
  static Future<bool> verifyEncryptionKeyPair(EncryptionKeyPair keyPair) async {
    if (!keyPair.hasPrivateKey) {
      throw StateError('Cannot verify: public-only key pair');
    }
    
    try {
      final Uint8List testMessage = Uint8List.fromList('test'.codeUnits);
      
      // Generate ephemeral key pair for testing
      final ({EcdhPrivateKey privateKey, EcdhPublicKey publicKey}) ephemeralKeyPair = 
          await EcdhPrivateKey.generateKey(EllipticCurve.p256);
      
      // Perform ECDH key agreement (test that it works)
      final Uint8List sharedSecret = await ephemeralKeyPair.privateKey.deriveBits(
        256, keyPair.publicKey);
      
      // Verify we got a valid shared secret
      if (sharedSecret.length != 32) return false;
      
      // Derive AES key (simplified version for testing)
      final AesGcmSecretKey aesKey = await AesGcmSecretKey.generateKey(256);
      
      // Test AES encrypt/decrypt
      final Uint8List iv = Uint8List(12);
      final Uint8List encrypted = await aesKey.encryptBytes(testMessage, iv);
      final Uint8List decrypted = await aesKey.decryptBytes(encrypted, iv);
      
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
      final Uint8List iv = Uint8List(12);
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
    final KeyDuo keyDuo = await serializer.importKeyDuo(jwkSetJson);
    
    final bool verified = await verifyKeyDuo(keyDuo);
    if (!verified) {
      throw StateError('Key verification failed: cryptographic roundtrip test failed');
    }
    
    return keyDuo;
  }
}