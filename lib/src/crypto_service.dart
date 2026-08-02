/// Complete cryptographic operations service.
library;

import 'dart:convert';
import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';
import 'constants.dart';
import 'encryption_key_pair.dart';
import 'hex_codec.dart';
import 'sec1_public_key.dart';
import 'signing_key_pair.dart';
import 'symmetric_key.dart';

/// Simple cryptographic operations service - building blocks only
///
/// Provides basic encrypt/decrypt/sign/verify operations without validation.
/// Flutter app decides when to validate keys and handles error policy.
///
/// Uses ECDH + AES hybrid encryption for web compatibility.
///
/// Every operation takes the specific key pair it needs — [EncryptionKeyPair]
/// for encrypt/decrypt, [SigningKeyPair] for sign/verify — rather than a whole
/// `KeyDuo`. This keeps the two halves symmetric and means encrypting to a
/// recipient needs only their public key, exactly as verifying a signature
/// needs only the signer's public key.
class CryptoService {
  // ═══════════════════════════════════════════════════════════════════════════
  // Asymmetric Operations - ECDH + AES Hybrid Encryption
  // ═══════════════════════════════════════════════════════════════════════════
  
  /// Encrypt data to [recipient] using ECDH + AES hybrid encryption
  ///
  /// Only the recipient's public key is used, so [recipient] may be a
  /// public-only key pair — a sender never needs the recipient's private key.
  ///
  /// The result has a fixed-size header — see [CryptoSizes.hybridHeaderLength]:
  ///
  /// ```
  /// | ephemeral SEC1 public key | HKDF salt | AES-GCM IV | ciphertext + tag |
  /// |         65 bytes          | 32 bytes  |  12 bytes  |     variable     |
  /// ```
  ///
  /// Process:
  /// 1. Generate ephemeral ECDH key pair
  /// 2. Perform ECDH key agreement with recipient's public key
  /// 3. Derive AES key from shared secret using HKDF with a random salt
  /// 4. Encrypt data with AES-GCM under a random IV
  /// 5. Return the ephemeral public key, salt, IV and ciphertext
  static Future<Uint8List> encrypt(
      Uint8List data, EncryptionKeyPair recipient) async {
    // 1. Generate ephemeral ECDH key pair
    final ({EcdhPrivateKey privateKey, EcdhPublicKey publicKey}) ephemeralKeyPair = 
        await EcdhPrivateKey.generateKey(EllipticCurve.p256);
    
    // 2. Perform ECDH key agreement
    final Uint8List sharedSecret = await ephemeralKeyPair.privateKey.deriveBits(
      256, recipient.publicKey);
    
    // 3. Generate random HKDF salt
    final Uint8List salt = _generateSalt();

    // 4. Derive AES key from shared secret with random salt
    final AesGcmSecretKey aesKey = await _deriveAesKey(sharedSecret, salt);

    // 5. Generate random IV for AES-GCM
    final Uint8List iv = _generateIV();

    // 6. Encrypt data with AES-GCM
    final Uint8List ciphertext = await aesKey.encryptBytes(data, iv);

    // 7. Export the ephemeral public key as a fixed 65-byte SEC1 point
    final Uint8List ephemeralPublicKeyBytes = Sec1PublicKey.validateRaw(
      await ephemeralKeyPair.publicKey.exportRawKey());

    // 8. Concatenate the fixed header and the ciphertext
    final Uint8List result =
        Uint8List(CryptoSizes.hybridHeaderLength + ciphertext.length);
    result.setRange(0, _saltOffset, ephemeralPublicKeyBytes);
    result.setRange(_saltOffset, _ivOffset, salt);
    result.setRange(_ivOffset, CryptoSizes.hybridHeaderLength, iv);
    result.setRange(CryptoSizes.hybridHeaderLength, result.length, ciphertext);

    return result;
  }
  
  /// Decrypt data addressed to [recipient] using ECDH + AES hybrid decryption
  ///
  /// Requires the recipient's private key, so unlike [encrypt] this cannot be
  /// done with a public-only key pair.
  ///
  /// Process:
  /// 1. Split the fixed header into ephemeral public key, salt and IV
  /// 2. Perform ECDH key agreement with the ephemeral public key
  /// 3. Derive AES key from shared secret using HKDF
  /// 4. Decrypt data with AES-GCM
  ///
  /// Every field is at a constant offset, so there is no length to parse and
  /// no attacker-controlled size to bound.
  ///
  /// Throws [StateError] if [recipient] is a public-only key pair.
  /// Throws [FormatException] if [data] is too short to be well formed or the
  /// embedded ephemeral key is not a valid P-256 point.
  static Future<Uint8List> decrypt(
      Uint8List data, EncryptionKeyPair recipient) async {
    final EcdhPrivateKey? privateKey = recipient.privateKey;
    if (privateKey == null) {
      throw StateError('Cannot decrypt: public-only encryption key pair');
    }

    const int minLength =
        CryptoSizes.hybridHeaderLength + CryptoSizes.aesGcmTagLength;
    if (data.length < minLength) {
      throw FormatException(
        'Encrypted data must be at least $minLength bytes '
        '(got ${data.length})',
      );
    }

    // 1. Split the fixed-size header. importPublicKeyRaw enforces the 04 tag
    //    and rejects points that are not on P-256.
    final EncryptionKeyPair ephemeral = await EncryptionKeyPair.importPublicKeyRaw(
      Uint8List.sublistView(data, 0, _saltOffset));
    final Uint8List salt = Uint8List.sublistView(data, _saltOffset, _ivOffset);
    final Uint8List iv =
        Uint8List.sublistView(data, _ivOffset, CryptoSizes.hybridHeaderLength);
    final Uint8List ciphertext =
        Uint8List.sublistView(data, CryptoSizes.hybridHeaderLength);

    // 2. Perform ECDH key agreement
    final Uint8List sharedSecret =
        await privateKey.deriveBits(256, ephemeral.publicKey);

    // 3. Derive AES key from shared secret with the transmitted salt
    final AesGcmSecretKey aesKey = await _deriveAesKey(sharedSecret, salt);

    // 4. Decrypt with AES-GCM. Authentication covers the ciphertext, and the
    //    salt and IV are covered in effect: altering either yields a key or
    //    nonce under which the tag cannot verify.
    return await aesKey.decryptBytes(ciphertext, iv);
  }
  
  /// Sign data with [signer]'s private key
  ///
  /// Throws [StateError] if [signer] is a public-only key pair.
  static Future<Uint8List> sign(Uint8List data, SigningKeyPair signer) async {
    return await signer.signBytes(data);
  }

  /// Verify a signature with [verifier]'s public key
  ///
  /// Only the public key is used, so [verifier] may be a public-only key pair.
  static Future<bool> verifySignature(
      Uint8List data, Uint8List signature, SigningKeyPair verifier) async {
    return await verifier.verifyBytes(signature, data);
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
  ///
  /// Throws [FormatException] if [data] is too short to be well formed.
  static Future<Uint8List> decryptSymmetric(Uint8List data, SymmetricKey symmetricKey) async {
    const int minLength =
        CryptoSizes.aesGcmIvLength + CryptoSizes.aesGcmTagLength;
    if (data.length < minLength) {
      throw FormatException(
        'Encrypted data must be at least $minLength bytes (got ${data.length})',
      );
    }

    final Uint8List iv = data.sublist(0, CryptoSizes.aesGcmIvLength);
    final Uint8List ciphertext = data.sublist(CryptoSizes.aesGcmIvLength);
    
    return await symmetricKey.internal.decryptBytes(ciphertext, iv);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // Convenience Methods (String-based)
  // ═══════════════════════════════════════════════════════════════════════════
  
  /// Encrypt a string to [recipient] using ECDH + AES, return base64
  ///
  /// Ciphertext is base64 rather than hex because it is variable-length binary;
  /// hex is reserved for fixed-width values (public keys, signatures).
  static Future<String> encryptString(
      String data, EncryptionKeyPair recipient) async {
    final Uint8List dataBytes = utf8.encode(data);
    final Uint8List encryptedBytes = await encrypt(dataBytes, recipient);
    return base64.encode(encryptedBytes);
  }

  /// Decrypt a base64 string addressed to [recipient] using ECDH + AES
  ///
  /// Throws [StateError] if [recipient] is a public-only key pair.
  static Future<String> decryptString(
      String base64Data, EncryptionKeyPair recipient) async {
    final Uint8List encryptedBytes = base64.decode(base64Data);
    final Uint8List decryptedBytes = await decrypt(encryptedBytes, recipient);
    return utf8.decode(decryptedBytes);
  }

  /// Sign a string with [signer], returning the signature as 128-char hex
  static Future<String> signString(String data, SigningKeyPair signer) async {
    final Uint8List dataBytes = utf8.encode(data);
    return HexCodec.encode(await sign(dataBytes, signer));
  }

  /// Verify a 128-char hex signature with [verifier]
  ///
  /// Throws [FormatException] if [signatureHex] is not 128 hex characters.
  static Future<bool> verifySignatureString(
      String data, String signatureHex, SigningKeyPair verifier) async {
    final Uint8List signatureBytes = HexCodec.decode(
      signatureHex,
      expectedLength: CryptoSizes.ecdsaP256SignatureLength * 2,
    );
    final Uint8List dataBytes = utf8.encode(data);
    return await verifySignature(dataBytes, signatureBytes, verifier);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // Private Helper Methods
  // ═══════════════════════════════════════════════════════════════════════════
  
  /// Derive AES-256-GCM key from shared secret using HKDF with random salt
  static Future<AesGcmSecretKey> _deriveAesKey(Uint8List sharedSecret, Uint8List salt) async {
    // Domain separation info for HKDF
    final Uint8List info = utf8.encode('dart-jwk-duo-ecdh-aes');

    // Import shared secret as HKDF key
    final HkdfSecretKey hkdfKey = await HkdfSecretKey.importRawKey(sharedSecret);

    // Derive 256 bits (32 bytes) for AES-256 using the provided random salt
    final Uint8List derivedKey = await hkdfKey.deriveBits(256, Hash.sha256, salt, info);

    // Import derived key as AES-GCM key
    return await AesGcmSecretKey.importRawKey(derivedKey);
  }

  /// Generate random HKDF salt
  static Uint8List _generateSalt() {
    final Uint8List salt = Uint8List(CryptoSizes.hkdfSaltLength);
    fillRandomBytes(salt);
    return salt;
  }

  /// Generate random AES-GCM IV
  static Uint8List _generateIV() {
    final Uint8List iv = Uint8List(CryptoSizes.aesGcmIvLength);
    fillRandomBytes(iv);
    return iv;
  }

  /// Byte offset of the HKDF salt within an encrypted blob.
  static const int _saltOffset = CryptoSizes.ecP256Sec1PublicKeyLength;

  /// Byte offset of the AES-GCM IV within an encrypted blob.
  static const int _ivOffset = _saltOffset + CryptoSizes.hkdfSaltLength;
}