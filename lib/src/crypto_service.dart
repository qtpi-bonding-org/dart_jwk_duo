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
class CryptoService {
  // ═══════════════════════════════════════════════════════════════════════════
  // Asymmetric Operations - Simple building blocks
  // ═══════════════════════════════════════════════════════════════════════════
  
  static Future<Uint8List> encrypt(Uint8List data, KeyDuo keyDuo) async {
    // Use WebCrypto directly (just like existing KeyDuo methods)
    return await keyDuo.encryption.publicKey.encryptBytes(data);
  }
  
  static Future<Uint8List> decrypt(Uint8List data, KeyDuo keyDuo) async {
    final privateKey = keyDuo.encryption.privateKey;
    if (privateKey == null) {
      throw StateError('Cannot decrypt: KeyDuo has no private key');
    }
    // Use WebCrypto directly (just like existing KeyDuo methods)
    return await privateKey.decryptBytes(data);
  }
  
  static Future<Uint8List> sign(Uint8List data, KeyDuo keyDuo) async {
    // Use concrete SigningKeyPair method (which uses WebCrypto)
    return await keyDuo.signingKeyPair.signBytes(data);
  }
  
  static Future<bool> verifySignature(Uint8List data, Uint8List signature, KeyDuo keyDuo) async {
    // Use concrete SigningKeyPair method (which uses WebCrypto)
    return await keyDuo.signingKeyPair.verifyBytes(signature, data);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // Symmetric Operations (SymmetricKey-based) - Use WebCrypto directly
  // ═══════════════════════════════════════════════════════════════════════════
  
  static Future<Uint8List> encryptSymmetric(Uint8List data, SymmetricKey symmetricKey) async {
    final iv = Uint8List(12);
    fillRandomBytes(iv);
    
    // Use WebCrypto directly (just like KeyDuo does)
    final Uint8List ciphertext = await symmetricKey.internal.encryptBytes(data, iv);
    
    // Combine IV + ciphertext
    final result = Uint8List(iv.length + ciphertext.length);
    result.setRange(0, iv.length, iv);
    result.setRange(iv.length, result.length, ciphertext);
    
    return result;
  }
  
  static Future<Uint8List> decryptSymmetric(Uint8List data, SymmetricKey symmetricKey) async {
    if (data.length < 12) {
      throw ArgumentError('Ciphertext too short to contain IV (minimum 12 bytes)');
    }
    
    final iv = data.sublist(0, 12);
    final ciphertext = data.sublist(12);
    
    // Use WebCrypto directly (just like KeyDuo does)
    return await symmetricKey.internal.decryptBytes(ciphertext, iv);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // Convenience Methods (String-based) - Use WebCrypto via above methods
  // ═══════════════════════════════════════════════════════════════════════════
  
  static Future<String> encryptString(String data, KeyDuo keyDuo) async {
    final dataBytes = utf8.encode(data);
    final encryptedBytes = await encrypt(dataBytes, keyDuo);
    return base64.encode(encryptedBytes);
  }
  
  static Future<String> decryptString(String base64Data, KeyDuo keyDuo) async {
    final encryptedBytes = base64.decode(base64Data);
    final decryptedBytes = await decrypt(encryptedBytes, keyDuo);
    return utf8.decode(decryptedBytes);
  }
  
  static Future<String> signString(String data, KeyDuo keyDuo) async {
    final dataBytes = utf8.encode(data);
    final signatureBytes = await sign(dataBytes, keyDuo);
    return signatureBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
  
  static Future<bool> verifySignatureString(String data, String signatureHex, KeyDuo keyDuo) async {
    final dataBytes = utf8.encode(data);
    final signatureBytes = Uint8List(signatureHex.length ~/ 2);
    
    for (int i = 0; i < signatureBytes.length; i++) {
      signatureBytes[i] = int.parse(signatureHex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    
    return await verifySignature(dataBytes, signatureBytes, keyDuo);
  }
}