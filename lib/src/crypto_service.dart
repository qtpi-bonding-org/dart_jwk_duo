/// Complete cryptographic operations service.
library;

import 'dart:convert';
import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';
import 'key_duo.dart';
import 'symmetric_key.dart';

/// Simple cryptographic operations service - building blocks only
/// 
/// Provides basic encrypt/decrypt/sign/verify operations without validation.
/// Flutter app decides when to validate keys and handles error policy.
/// 
/// Uses ECDH + AES hybrid encryption for web compatibility.
class CryptoService {
  // ═══════════════════════════════════════════════════════════════════════════
  // Asymmetric Operations - ECDH + AES Hybrid Encryption
  // ═══════════════════════════════════════════════════════════════════════════
  
  /// Encrypt data using ECDH + AES hybrid encryption
  /// 
  /// Process:
  /// 1. Generate ephemeral ECDH key pair
  /// 2. Perform ECDH key agreement with recipient's public key
  /// 3. Derive AES key from shared secret using HKDF
  /// 4. Encrypt data with AES-GCM
  /// 5. Return ephemeral public key + encrypted data
  static Future<Uint8List> encrypt(Uint8List data, KeyDuo keyDuo) async {
    // 1. Generate ephemeral ECDH key pair
    final ({EcdhPrivateKey privateKey, EcdhPublicKey publicKey}) ephemeralKeyPair = 
        await EcdhPrivateKey.generateKey(EllipticCurve.p256);
    
    // 2. Perform ECDH key agreement
    final Uint8List sharedSecret = await ephemeralKeyPair.privateKey.deriveBits(
      256, keyDuo.encryption.publicKey);
    
    // 3. Derive AES key from shared secret
    final AesGcmSecretKey aesKey = await _deriveAesKey(sharedSecret);
    
    // 4. Generate random IV for AES-GCM
    final Uint8List iv = _generateIV();
    
    // 5. Encrypt data with AES-GCM
    final Uint8List ciphertext = await aesKey.encryptBytes(data, iv);
    
    // 6. Export ephemeral public key
    final Map<String, dynamic> ephemeralPublicJwk = await ephemeralKeyPair.publicKey.exportJsonWebKey();
    final Uint8List ephemeralPublicKeyBytes = utf8.encode(jsonEncode(ephemeralPublicJwk));
    
    // 7. Combine: ephemeral_key_length(4) + ephemeral_key + iv(12) + ciphertext
    final Uint8List result = Uint8List(4 + ephemeralPublicKeyBytes.length + iv.length + ciphertext.length);
    int offset = 0;
    
    // Write ephemeral key length (4 bytes, big-endian)
    result.setRange(offset, offset + 4, _uint32ToBytes(ephemeralPublicKeyBytes.length));
    offset += 4;
    
    // Write ephemeral public key
    result.setRange(offset, offset + ephemeralPublicKeyBytes.length, ephemeralPublicKeyBytes);
    offset += ephemeralPublicKeyBytes.length;
    
    // Write IV
    result.setRange(offset, offset + iv.length, iv);
    offset += iv.length;
    
    // Write ciphertext
    result.setRange(offset, offset + ciphertext.length, ciphertext);
    
    return result;
  }
  
  /// Decrypt data using ECDH + AES hybrid decryption
  /// 
  /// Process:
  /// 1. Extract ephemeral public key, IV, and ciphertext
  /// 2. Perform ECDH key agreement with ephemeral public key
  /// 3. Derive AES key from shared secret using HKDF
  /// 4. Decrypt data with AES-GCM
  static Future<Uint8List> decrypt(Uint8List data, KeyDuo keyDuo) async {
    final EcdhPrivateKey? privateKey = keyDuo.encryption.privateKey;
    if (privateKey == null) {
      throw StateError('Cannot decrypt: KeyDuo has no private key');
    }
    
    if (data.length < 16) { // Minimum: 4 + 1 + 12 = 17 bytes
      throw ArgumentError('Encrypted data too short');
    }
    
    int offset = 0;
    
    // 1. Read ephemeral key length
    final int ephemeralKeyLength = _bytesToUint32(data.sublist(offset, offset + 4));
    offset += 4;
    
    if (data.length < offset + ephemeralKeyLength + 12) {
      throw ArgumentError('Invalid encrypted data format');
    }
    
    // 2. Read and import ephemeral public key
    final Uint8List ephemeralKeyBytes = data.sublist(offset, offset + ephemeralKeyLength);
    offset += ephemeralKeyLength;
    
    final Map<String, dynamic> ephemeralPublicJwk = jsonDecode(utf8.decode(ephemeralKeyBytes)) as Map<String, dynamic>;
    final EcdhPublicKey ephemeralPublicKey = await EcdhPublicKey.importJsonWebKey(
      ephemeralPublicJwk, EllipticCurve.p256);
    
    // 3. Read IV
    final Uint8List iv = data.sublist(offset, offset + 12);
    offset += 12;
    
    // 4. Read ciphertext
    final Uint8List ciphertext = data.sublist(offset);
    
    // 5. Perform ECDH key agreement
    final Uint8List sharedSecret = await privateKey.deriveBits(256, ephemeralPublicKey);
    
    // 6. Derive AES key from shared secret
    final AesGcmSecretKey aesKey = await _deriveAesKey(sharedSecret);
    
    // 7. Decrypt with AES-GCM
    return await aesKey.decryptBytes(ciphertext, iv);
  }
  
  /// Sign data with KeyDuo's signing key
  static Future<Uint8List> sign(Uint8List data, KeyDuo keyDuo) async {
    return await keyDuo.signingKeyPair.signBytes(data);
  }
  
  /// Verify signature with KeyDuo's signing key
  static Future<bool> verifySignature(Uint8List data, Uint8List signature, KeyDuo keyDuo) async {
    return await keyDuo.signingKeyPair.verifyBytes(signature, data);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // Symmetric Operations (SymmetricKey-based)
  // ═══════════════════════════════════════════════════════════════════════════
  
  /// Encrypt data with symmetric key
  static Future<Uint8List> encryptSymmetric(Uint8List data, SymmetricKey symmetricKey) async {
    final Uint8List iv = _generateIV();
    final Uint8List ciphertext = await symmetricKey.internal.encryptBytes(data, iv);
    
    // Combine IV + ciphertext
    final Uint8List result = Uint8List(iv.length + ciphertext.length);
    result.setRange(0, iv.length, iv);
    result.setRange(iv.length, result.length, ciphertext);
    
    return result;
  }
  
  /// Decrypt data with symmetric key
  static Future<Uint8List> decryptSymmetric(Uint8List data, SymmetricKey symmetricKey) async {
    if (data.length < 12) {
      throw ArgumentError('Ciphertext too short to contain IV (minimum 12 bytes)');
    }
    
    final Uint8List iv = data.sublist(0, 12);
    final Uint8List ciphertext = data.sublist(12);
    
    return await symmetricKey.internal.decryptBytes(ciphertext, iv);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // Convenience Methods (String-based)
  // ═══════════════════════════════════════════════════════════════════════════
  
  /// Encrypt string using ECDH + AES, return base64
  static Future<String> encryptString(String data, KeyDuo keyDuo) async {
    final Uint8List dataBytes = utf8.encode(data);
    final Uint8List encryptedBytes = await encrypt(dataBytes, keyDuo);
    return base64.encode(encryptedBytes);
  }
  
  /// Decrypt base64 string using ECDH + AES
  static Future<String> decryptString(String base64Data, KeyDuo keyDuo) async {
    final Uint8List encryptedBytes = base64.decode(base64Data);
    final Uint8List decryptedBytes = await decrypt(encryptedBytes, keyDuo);
    return utf8.decode(decryptedBytes);
  }
  
  /// Sign string, return hex signature
  static Future<String> signString(String data, KeyDuo keyDuo) async {
    final Uint8List dataBytes = utf8.encode(data);
    final Uint8List signatureBytes = await sign(dataBytes, keyDuo);
    return signatureBytes.map((int b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
  
  /// Verify hex signature
  static Future<bool> verifySignatureString(String data, String signatureHex, KeyDuo keyDuo) async {
    final Uint8List dataBytes = utf8.encode(data);
    final Uint8List signatureBytes = Uint8List(signatureHex.length ~/ 2);
    
    for (int i = 0; i < signatureBytes.length; i++) {
      signatureBytes[i] = int.parse(signatureHex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    
    return await verifySignature(dataBytes, signatureBytes, keyDuo);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // Private Helper Methods
  // ═══════════════════════════════════════════════════════════════════════════
  
  /// Derive AES-256-GCM key from shared secret using HKDF
  static Future<AesGcmSecretKey> _deriveAesKey(Uint8List sharedSecret) async {
    // Use HKDF with SHA-256 to derive AES key
    // Info parameter for domain separation
    final Uint8List info = utf8.encode('dart-jwk-duo-ecdh-aes');
    
    // Import shared secret as HKDF key
    final HkdfSecretKey hkdfKey = await HkdfSecretKey.importRawKey(sharedSecret);
    
    // Derive 256 bits (32 bytes) for AES-256
    final Uint8List derivedKey = await hkdfKey.deriveBits(256, Hash.sha256, Uint8List(0), info);
    
    // Import derived key as AES-GCM key
    return await AesGcmSecretKey.importRawKey(derivedKey);
  }
  
  /// Generate random 12-byte IV for AES-GCM
  static Uint8List _generateIV() {
    final Uint8List iv = Uint8List(12);
    fillRandomBytes(iv);
    return iv;
  }
  
  /// Convert uint32 to 4 bytes (big-endian)
  static Uint8List _uint32ToBytes(int value) {
    final Uint8List bytes = Uint8List(4);
    bytes[0] = (value >> 24) & 0xFF;
    bytes[1] = (value >> 16) & 0xFF;
    bytes[2] = (value >> 8) & 0xFF;
    bytes[3] = value & 0xFF;
    return bytes;
  }
  
  /// Convert 4 bytes to uint32 (big-endian)
  static int _bytesToUint32(Uint8List bytes) {
    return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
  }
}