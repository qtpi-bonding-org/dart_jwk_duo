import 'dart:convert';
import 'dart:math';
import 'package:flutter_test/flutter_test.dart';
import 'package:jwk_duo/src/jwk_thumbprint.dart';
import 'package:jwk_duo/src/exported_jwk.dart';
import 'package:jwk_duo/src/constants.dart';
import 'package:jwk_duo/src/signing_key_pair.dart';
import 'package:jwk_duo/src/encryption_key_pair.dart';
import 'package:jwk_duo/src/key_duo_generator.dart';
import 'package:jwk_duo/src/key_duo_serializer.dart';
import 'package:jwk_duo/src/interfaces.dart';
import 'package:webcrypto/webcrypto.dart';

// Property-based test iteration counts
const int lightweightIterations = 50; // For fast operations (hashing, object creation)
const int expensiveIterations = 5;    // For slow operations (RSA key generation)

void main() {
  group('JWK Duo', () {
    test('placeholder test', () {
      // TODO: Add actual tests as implementation progresses
      expect(true, isTrue);
    });
  });

  group('JWK Thumbprint', () {
    /// **Feature: jwk-duo, Property 12: JWK thumbprint consistency**
    /// **Validates: Requirements 6.3, 6.4**
    test('property test - JWK thumbprint consistency', () async {
      final random = Random();
      
      // Run property test with lightweight iterations
      for (int i = 0; i < lightweightIterations; i++) {
        // Generate a random RSA JWK with consistent structure
        final jwk = _generateRandomRsaJwk(random);
        
        // Calculate thumbprint multiple times
        final thumbprint1 = await calculateJwkThumbprint(jwk);
        final thumbprint2 = await calculateJwkThumbprint(jwk);
        
        // Property: Thumbprint should be consistent across multiple calculations
        expect(thumbprint1, equals(thumbprint2), 
               reason: 'Thumbprint should be consistent for the same JWK');
        
        // Property: Thumbprint should be a valid base64url string without padding
        expect(thumbprint1, matches(RegExp(r'^[A-Za-z0-9_-]+$')), 
               reason: 'Thumbprint should be valid base64url without padding');
        
        // Property: Thumbprint should have reasonable length (SHA-256 hash)
        // Base64url encoding of 32 bytes (256 bits) should be 43 characters
        expect(thumbprint1.length, equals(43), 
               reason: 'SHA-256 thumbprint should be 43 characters when base64url encoded');
        
        // Property: Different JWKs should produce different thumbprints
        final differentJwk = _generateRandomRsaJwk(random);
        final differentThumbprint = await calculateJwkThumbprint(differentJwk);
        
        // Only check if JWKs are actually different
        if (!_areJwksEqual(jwk, differentJwk)) {
          expect(thumbprint1, isNot(equals(differentThumbprint)), 
                 reason: 'Different JWKs should produce different thumbprints');
        }
      }
    });

    test('JWK thumbprint validation errors', () async {
      // Test missing required fields
      expect(
        () => calculateJwkThumbprint({'kty': 'RSA', 'n': 'test'}),
        throwsA(isA<ArgumentError>()),
        reason: 'Should throw when missing required field "e"',
      );
      
      expect(
        () => calculateJwkThumbprint({'kty': 'RSA', 'e': 'AQAB'}),
        throwsA(isA<ArgumentError>()),
        reason: 'Should throw when missing required field "n"',
      );
      
      expect(
        () => calculateJwkThumbprint({'n': 'test', 'e': 'AQAB'}),
        throwsA(isA<ArgumentError>()),
        reason: 'Should throw when missing required field "kty"',
      );
      
      // Test unsupported key type
      expect(
        () => calculateJwkThumbprint({'kty': 'EC', 'n': 'test', 'e': 'AQAB'}),
        throwsA(isA<ArgumentError>()),
        reason: 'Should throw for unsupported key type',
      );
    });
  });

  group('ExportedJwk DTO', () {
    /// **Feature: jwk-duo, Property 11: Export returns Type-Safe DTO**
    /// **Validates: Requirements 5.1, 5.2**
    test('property test - Export returns Type-Safe DTO', () async {
      final Random random = Random();
      
      // Run property test with lightweight iterations
      for (int i = 0; i < lightweightIterations; i++) {
        // Generate random valid JWK data for both signing and encryption
        final Map<String, dynamic> signingJwkData = _generateValidRsaJwkData(random);
        final Map<String, dynamic> encryptionJwkData = _generateValidRsaJwkData(random);
        
        // Test signing key DTO
        final String signingKid = 'test-signing-${random.nextInt(1000)}';
        
        final ExportedJwk signingExport = ExportedJwk(
          keyData: signingJwkData,
          keyId: signingKid,
          
          alg: JwkAlgorithm.ps256,
          use: JwkUse.signature,
        );
        
        // Property: DTO must contain all required metadata
        expect(signingExport.keyId, equals(signingKid));
        expect(signingExport.alg, equals(JwkAlgorithm.ps256));
        expect(signingExport.use, equals(JwkUse.signature));
        
        // Property: toJson() must include metadata
        final Map<String, dynamic> signingJson = signingExport.toJson();
        expect(signingJson['kid'], equals(signingKid));
        expect(signingJson['alg'], equals(JwkAlgorithm.ps256));
        expect(signingJson['use'], equals(JwkUse.signature));
        expect(signingJson['kty'], equals(JwkKeyType.rsa));
        
        // Test encryption key DTO
        final String encryptionKid = 'test-encryption-${random.nextInt(1000)}';
        
        final ExportedJwk encryptionExport = ExportedJwk(
          keyData: encryptionJwkData,
          keyId: encryptionKid,
          
          alg: JwkAlgorithm.rsaOaep256,
          use: JwkUse.encryption,
        );
        
        // Property: DTO must contain all required metadata
        expect(encryptionExport.keyId, equals(encryptionKid));
        expect(encryptionExport.alg, equals(JwkAlgorithm.rsaOaep256));
        expect(encryptionExport.use, equals(JwkUse.encryption));
        
        // Property: toJson() must include metadata
        final Map<String, dynamic> encryptionJson = encryptionExport.toJson();
        expect(encryptionJson['kid'], equals(encryptionKid));
        expect(encryptionJson['alg'], equals(JwkAlgorithm.rsaOaep256));
        expect(encryptionJson['use'], equals(JwkUse.encryption));
        expect(encryptionJson['kty'], equals(JwkKeyType.rsa));
      }
    });

    test('ExportedJwk validation errors', () {
      final Map<String, dynamic> jwkData = _generateValidRsaJwkData(Random());
      
      // Test invalid algorithm/use combinations
      expect(
        () => ExportedJwk(
          keyData: jwkData,
          keyId: 'test',
          
          alg: JwkAlgorithm.ps256,
          use: JwkUse.encryption, // Wrong use for PS256
        ),
        throwsA(isA<ArgumentError>()),
        reason: 'Should throw for PS256 with encryption use',
      );
      
      expect(
        () => ExportedJwk(
          keyData: jwkData,
          keyId: 'test',
          
          alg: JwkAlgorithm.rsaOaep256,
          use: JwkUse.signature, // Wrong use for RSA-OAEP-256
        ),
        throwsA(isA<ArgumentError>()),
        reason: 'Should throw for RSA-OAEP-256 with signature use',
      );
    });

    /// **Feature: jwk-duo, Property 13: Public key export safety**
    /// **Validates: Requirements 3.1, 3.4**
    test('property test - Public key export safety', () async {
      final Random random = Random();
      
      // Run property test with lightweight iterations
      for (int i = 0; i < lightweightIterations; i++) {
        // Generate JWK with private components
        final Map<String, dynamic> privateJwkData = _generateValidRsaJwkData(random, includePrivate: true);
        
        // Create ExportedJwk with private key
        final ExportedJwk privateExport = ExportedJwk(
          keyData: privateJwkData,
          keyId: 'test-${random.nextInt(1000)}',
          
          alg: JwkAlgorithm.ps256,
          use: JwkUse.signature,
        );
        
        // Convert to public-only version
        final ExportedJwk publicExport = privateExport.toPublicOnly();
        
        // Property: Public export must NOT contain private RSA components
        final Map<String, dynamic> publicJson = publicExport.toJson();
        expect(publicJson.containsKey('d'), isFalse, reason: 'Public key must not contain private exponent d');
        expect(publicJson.containsKey('p'), isFalse, reason: 'Public key must not contain prime factor p');
        expect(publicJson.containsKey('q'), isFalse, reason: 'Public key must not contain prime factor q');
        expect(publicJson.containsKey('dp'), isFalse, reason: 'Public key must not contain CRT exponent dp');
        expect(publicJson.containsKey('dq'), isFalse, reason: 'Public key must not contain CRT exponent dq');
        expect(publicJson.containsKey('qi'), isFalse, reason: 'Public key must not contain CRT coefficient qi');
        
        // Property: Public export must preserve public components and metadata
        expect(publicJson['kty'], equals(JwkKeyType.rsa));
        expect(publicJson['n'], equals(privateJwkData['n']));
        expect(publicJson['e'], equals(privateJwkData['e']));
        expect(publicJson['kid'], equals(privateExport.keyId));
        expect(publicJson['alg'], equals(privateExport.alg));
        expect(publicJson['use'], equals(privateExport.use));
        
        // Property: Metadata should be preserved
        expect(publicExport.keyId, equals(privateExport.keyId));
        expect(publicExport.alg, equals(privateExport.alg));
        expect(publicExport.use, equals(privateExport.use));
      }
    });
  });

  group('SigningKeyPair', () {
    /// **Feature: jwk-duo, Property 4: Signing key export includes correct metadata**
    /// **Validates: Requirements 2.3, 3.2**
    test('property test - Signing key export includes correct metadata', () async {
      
      // Run property test with expensive iterations (RSA key generation is expensive)
      for (int i = 0; i < expensiveIterations; i++) {
        // Generate RSA-PSS key pair for testing
        final KeyPair<RsaPssPrivateKey, RsaPssPublicKey> keyPair = await RsaPssPrivateKey.generateKey(
          RsaParameters.modulusLength,
          BigInt.from(RsaParameters.publicExponent),
          Hash.sha256,
        );
        
        // Test with default configuration
        final SigningKeyPair signingKeyPair = SigningKeyPair(
          privateKey: keyPair.privateKey,
          publicKey: keyPair.publicKey,
        );
        
        // Test private key export
        final ExportedJwk privateExport = await signingKeyPair.exportPrivateKey();
        
        // Property: Private key export must have correct algorithm
        expect(privateExport.alg, equals(JwkAlgorithm.ps256),
               reason: 'Signing key must have PS256 algorithm');
        
        // Property: Private key export must have correct use
        expect(privateExport.use, equals(JwkUse.signature),
               reason: 'Signing key must have signature use');
        
        // Property: Private key export must have valid key ID (RFC 7638 thumbprint)
        expect(privateExport.keyId, isNotEmpty,
               reason: 'Key ID must not be empty');
        expect(privateExport.keyId, matches(RegExp(r'^[A-Za-z0-9_-]+$')),
               reason: 'Key ID should be valid base64url format');
        
        // Property: Key ID should be consistent across exports
        final String keyId1 = await signingKeyPair.calculateKeyId();
        final String keyId2 = await signingKeyPair.calculateKeyId();
        expect(keyId1, equals(keyId2),
               reason: 'Key ID should be consistent across calculations');
        expect(privateExport.keyId, equals(keyId1),
               reason: 'Export kid should match calculated key ID');
        
        // Test public key export
        final ExportedJwk publicExport = await signingKeyPair.exportPublicKey();
        
        // Property: Public key export must have same metadata as private
        expect(publicExport.alg, equals(JwkAlgorithm.ps256),
               reason: 'Public key must have same algorithm as private');
        expect(publicExport.use, equals(JwkUse.signature),
               reason: 'Public key must have same use as private');
        expect(publicExport.keyId, equals(privateExport.keyId),
               reason: 'Public key must have same kid as private');
        
        // Property: Exported JSON must contain required metadata
        final Map<String, dynamic> privateJson = privateExport.toJson();
        expect(privateJson['alg'], equals(JwkAlgorithm.ps256));
        expect(privateJson['use'], equals(JwkUse.signature));
        expect(privateJson['kid'], equals(privateExport.keyId));
        expect(privateJson['kty'], equals(JwkKeyType.rsa));
        
        final Map<String, dynamic> publicJson = publicExport.toJson();
        expect(publicJson['alg'], equals(JwkAlgorithm.ps256));
        expect(publicJson['use'], equals(JwkUse.signature));
        expect(publicJson['kid'], equals(publicExport.keyId));
        expect(publicJson['kty'], equals(JwkKeyType.rsa));
        
        // Property: Public export must not contain private components
        expect(publicJson.containsKey('d'), isFalse,
               reason: 'Public key export must not contain private exponent');
        
        // Test with standard RFC 7638 key ID formatting
        final SigningKeyPair customKeyPair = SigningKeyPair(
          privateKey: keyPair.privateKey,
          publicKey: keyPair.publicKey,
          
        );
        
        final String customKeyId = await customKeyPair.calculateKeyId();
        expect(customKeyId, matches(RegExp(r'^[A-Za-z0-9_-]+$')),
               reason: 'Key ID should be RFC 7638 thumbprint format');
        
        final ExportedJwk customExport = await customKeyPair.exportPrivateKey();
        expect(customExport.keyId, equals(customKeyId),
               reason: 'Export should use custom key ID');
      }
    });

    /// **Feature: jwk-duo, Property 15: Signing key pair validation**
    /// **Validates: Security requirement for key pair integrity**
    test('property test - Signing key pair validation', () async {
      // Run property test with expensive iterations (RSA key generation is expensive)
      for (int i = 0; i < expensiveIterations; i++) {
        // Generate RSA-PSS key pair for testing
        final KeyPair<RsaPssPrivateKey, RsaPssPublicKey> keyPair = await RsaPssPrivateKey.generateKey(
          RsaParameters.modulusLength,
          BigInt.from(RsaParameters.publicExponent),
          Hash.sha256,
        );
        
        final SigningKeyPair signingKeyPair = SigningKeyPair(
          privateKey: keyPair.privateKey,
          publicKey: keyPair.publicKey,
        );
        
        // Property: Valid key pair should pass validation
        final bool isValid = await signingKeyPair.validateKeyPair();
        expect(isValid, isTrue,
               reason: 'Properly paired keys should validate successfully');
        
        // Test public-only key pair validation
        final SigningKeyPair publicOnlyKeyPair = SigningKeyPair.publicOnly(
          publicKey: keyPair.publicKey,
        );
        
        // Property: Public-only key pair should throw StateError
        expect(
          () => publicOnlyKeyPair.validateKeyPair(),
          throwsA(isA<StateError>()),
          reason: 'Public-only key pair should throw StateError on validation',
        );
      }
    });
  });

  group('EncryptionKeyPair', () {
    /// **Feature: jwk-duo, Property 5: Encryption key export includes correct metadata**
    /// **Validates: Requirements 2.4, 3.3**
    test('property test - Encryption key export includes correct metadata', () async {
      
      // Run property test with expensive iterations (RSA key generation is expensive)
      for (int i = 0; i < expensiveIterations; i++) {
        // Generate RSA-OAEP key pair for testing
        final KeyPair<RsaOaepPrivateKey, RsaOaepPublicKey> keyPair = await RsaOaepPrivateKey.generateKey(
          RsaParameters.modulusLength,
          BigInt.from(RsaParameters.publicExponent),
          Hash.sha256,
        );
        
        // Test with default configuration
        final EncryptionKeyPair encryptionKeyPair = EncryptionKeyPair(
          privateKey: keyPair.privateKey,
          publicKey: keyPair.publicKey,
        );
        
        // Test private key export
        final ExportedJwk privateExport = await encryptionKeyPair.exportPrivateKey();
        
        // Property: Private key export must have correct algorithm
        expect(privateExport.alg, equals(JwkAlgorithm.rsaOaep256),
               reason: 'Encryption key must have RSA-OAEP-256 algorithm');
        
        // Property: Private key export must have correct use
        expect(privateExport.use, equals(JwkUse.encryption),
               reason: 'Encryption key must have encryption use');
        
        // Property: Private key export must have valid key ID (RFC 7638 thumbprint)
        expect(privateExport.keyId, isNotEmpty,
               reason: 'Key ID must not be empty');
        expect(privateExport.keyId, matches(RegExp(r'^[A-Za-z0-9_-]+$')),
               reason: 'Key ID should be valid base64url format');
        
        // Property: Key ID should be consistent across exports
        final String keyId1 = await encryptionKeyPair.calculateKeyId();
        final String keyId2 = await encryptionKeyPair.calculateKeyId();
        expect(keyId1, equals(keyId2),
               reason: 'Key ID should be consistent across calculations');
        expect(privateExport.keyId, equals(keyId1),
               reason: 'Export kid should match calculated key ID');
        
        // Test public key export
        final ExportedJwk publicExport = await encryptionKeyPair.exportPublicKey();
        
        // Property: Public key export must have same metadata as private
        expect(publicExport.alg, equals(JwkAlgorithm.rsaOaep256),
               reason: 'Public key must have same algorithm as private');
        expect(publicExport.use, equals(JwkUse.encryption),
               reason: 'Public key must have same use as private');
        expect(publicExport.keyId, equals(privateExport.keyId),
               reason: 'Public key must have same kid as private');
        
        // Property: Exported JSON must contain required metadata
        final Map<String, dynamic> privateJson = privateExport.toJson();
        expect(privateJson['alg'], equals(JwkAlgorithm.rsaOaep256));
        expect(privateJson['use'], equals(JwkUse.encryption));
        expect(privateJson['kid'], equals(privateExport.keyId));
        expect(privateJson['kty'], equals(JwkKeyType.rsa));
        
        final Map<String, dynamic> publicJson = publicExport.toJson();
        expect(publicJson['alg'], equals(JwkAlgorithm.rsaOaep256));
        expect(publicJson['use'], equals(JwkUse.encryption));
        expect(publicJson['kid'], equals(publicExport.keyId));
        expect(publicJson['kty'], equals(JwkKeyType.rsa));
        
        // Property: Public export must not contain private components
        expect(publicJson.containsKey('d'), isFalse,
               reason: 'Public key export must not contain private exponent');
        
        // Test with standard RFC 7638 key ID formatting
        final EncryptionKeyPair customKeyPair = EncryptionKeyPair(
          privateKey: keyPair.privateKey,
          publicKey: keyPair.publicKey,
          
        );
        
        final String customKeyId = await customKeyPair.calculateKeyId();
        expect(customKeyId, matches(RegExp(r'^[A-Za-z0-9_-]+$')),
               reason: 'Key ID should be RFC 7638 thumbprint format');
        
        final ExportedJwk customExport = await customKeyPair.exportPrivateKey();
        expect(customExport.keyId, equals(customKeyId),
               reason: 'Export should use custom key ID');
      }
    });

    /// **Feature: jwk-duo, Property 16: Encryption key pair validation**
    /// **Validates: Security requirement for key pair integrity**
    test('property test - Encryption key pair validation', () async {
      // Run property test with expensive iterations (RSA key generation is expensive)
      for (int i = 0; i < expensiveIterations; i++) {
        // Generate RSA-OAEP key pair for testing
        final KeyPair<RsaOaepPrivateKey, RsaOaepPublicKey> keyPair = await RsaOaepPrivateKey.generateKey(
          RsaParameters.modulusLength,
          BigInt.from(RsaParameters.publicExponent),
          Hash.sha256,
        );
        
        final EncryptionKeyPair encryptionKeyPair = EncryptionKeyPair(
          privateKey: keyPair.privateKey,
          publicKey: keyPair.publicKey,
        );
        
        // Property: Valid key pair should pass validation
        final bool isValid = await encryptionKeyPair.validateKeyPair();
        expect(isValid, isTrue,
               reason: 'Properly paired keys should validate successfully');
        
        // Test public-only key pair validation
        final EncryptionKeyPair publicOnlyKeyPair = EncryptionKeyPair.publicOnly(
          publicKey: keyPair.publicKey,
        );
        
        // Property: Public-only key pair should throw StateError
        expect(
          () => publicOnlyKeyPair.validateKeyPair(),
          throwsA(isA<StateError>()),
          reason: 'Public-only key pair should throw StateError on validation',
        );
      }
    });
  });

  group('KeyDuo and KeyDuoGenerator', () {
    /// **Feature: jwk-duo, Property 1: Key generation produces correct key types**
    /// **Validates: Requirements 1.1, 1.2, 2.1, 2.2**
    test('property test - Key generation produces correct key types', () async {
      
      // Run property test with expensive iterations (RSA key generation is expensive)
      for (int i = 0; i < expensiveIterations; i++) {
        final KeyDuoGenerator generator = KeyDuoGenerator(
          modulusLength: RsaParameters.modulusLength,
        );
        final IKeyDuo keyDuo = await generator.generateKeyDuo();
        
        // Property: Key duo must contain signing key pair with correct types
        expect(keyDuo.signing, isA<IKeyPair<RsaPssPrivateKey, RsaPssPublicKey>>(),
               reason: 'Signing key pair must have RSA-PSS types');
        expect(keyDuo.signing.privateKey, isA<RsaPssPrivateKey>(),
               reason: 'Signing private key must be RSA-PSS type');
        expect(keyDuo.signing.publicKey, isA<RsaPssPublicKey>(),
               reason: 'Signing public key must be RSA-PSS type');
        
        // Property: Key duo must contain encryption key pair with correct types
        expect(keyDuo.encryption, isA<IKeyPair<RsaOaepPrivateKey, RsaOaepPublicKey>>(),
               reason: 'Encryption key pair must have RSA-OAEP types');
        expect(keyDuo.encryption.privateKey, isA<RsaOaepPrivateKey>(),
               reason: 'Encryption private key must be RSA-OAEP type');
        expect(keyDuo.encryption.publicKey, isA<RsaOaepPublicKey>(),
               reason: 'Encryption public key must be RSA-OAEP type');
        
        // Property: Signing key must export with correct metadata
        final ExportedJwk signingExport = await keyDuo.signing.exportPrivateKey();
        expect(signingExport.alg, equals(JwkAlgorithm.ps256),
               reason: 'Signing key must have PS256 algorithm');
        expect(signingExport.use, equals(JwkUse.signature),
               reason: 'Signing key must have signature use');
        
        // Property: Encryption key must export with correct metadata
        final ExportedJwk encryptionExport = await keyDuo.encryption.exportPrivateKey();
        expect(encryptionExport.alg, equals(JwkAlgorithm.rsaOaep256),
               reason: 'Encryption key must have RSA-OAEP-256 algorithm');
        expect(encryptionExport.use, equals(JwkUse.encryption),
               reason: 'Encryption key must have encryption use');
        
        // Property: Keys must be different (different thumbprints)
        expect(signingExport.keyId, isNot(equals(encryptionExport.keyId)),
               reason: 'Signing and encryption keys must have different key IDs');
      }
    });

    /// **Feature: jwk-duo, Property 2: Key generation uses correct cryptographic parameters**
    /// **Validates: Requirements 1.3, 1.4**
    test('property test - Key generation uses correct cryptographic parameters', () async {
      
      // Run property test with expensive iterations (RSA key generation is expensive)
      for (int i = 0; i < expensiveIterations; i++) {
        final KeyDuoGenerator generator = KeyDuoGenerator(modulusLength: RsaParameters.modulusLength);
        final IKeyDuo keyDuo = await generator.generateKeyDuo();
        
        // Export keys to inspect their parameters
        final ExportedJwk signingExport = await keyDuo.signing.exportPrivateKey();
        final ExportedJwk encryptionExport = await keyDuo.encryption.exportPrivateKey();
        
        final Map<String, dynamic> signingJson = signingExport.toJson();
        final Map<String, dynamic> encryptionJson = encryptionExport.toJson();
        
        // Property: Both keys must use RSA key type
        expect(signingJson['kty'], equals(JwkKeyType.rsa),
               reason: 'Signing key must use RSA key type');
        expect(encryptionJson['kty'], equals(JwkKeyType.rsa),
               reason: 'Encryption key must use RSA key type');
        
        // Property: Both keys must use standard public exponent (65537 = AQAB in base64url)
        expect(signingJson['e'], equals('AQAB'),
               reason: 'Signing key must use standard public exponent 65537');
        expect(encryptionJson['e'], equals('AQAB'),
               reason: 'Encryption key must use standard public exponent 65537');
        
        // Property: Both keys must have modulus of appropriate length for 2048-bit keys
        // Base64url encoding of 2048-bit (256 byte) modulus should be around 342-344 characters
        final String signingModulus = signingJson['n'] as String;
        final String encryptionModulus = encryptionJson['n'] as String;
        
        expect(signingModulus.length, greaterThanOrEqualTo(340),
               reason: 'Signing key modulus should be appropriate length for 2048-bit key (test)');
        expect(signingModulus.length, lessThanOrEqualTo(350),
               reason: 'Signing key modulus should not be too long for 2048-bit key (test)');
        
        expect(encryptionModulus.length, greaterThanOrEqualTo(340),
               reason: 'Encryption key modulus should be appropriate length for 2048-bit key (test)');
        expect(encryptionModulus.length, lessThanOrEqualTo(350),
               reason: 'Encryption key modulus should not be too long for 2048-bit key (test)');
        
        // Property: Keys must contain private exponent for private key exports
        expect(signingJson.containsKey('d'), isTrue,
               reason: 'Signing private key export must contain private exponent');
        expect(encryptionJson.containsKey('d'), isTrue,
               reason: 'Encryption private key export must contain private exponent');
        
        // Property: Private exponents must be non-empty
        expect(signingJson['d'], isNotEmpty,
               reason: 'Signing private exponent must not be empty');
        expect(encryptionJson['d'], isNotEmpty,
               reason: 'Encryption private exponent must not be empty');
      }
    });

    /// **Feature: jwk-duo, Property 3: Key duo contains both key pairs**
    /// **Validates: Requirements 1.5**
    test('property test - Key duo contains both key pairs', () async {
      
      // Run property test with expensive iterations (RSA key generation is expensive)
      for (int i = 0; i < expensiveIterations; i++) {
        final KeyDuoGenerator generator = KeyDuoGenerator(modulusLength: RsaParameters.modulusLength);
        final IKeyDuo keyDuo = await generator.generateKeyDuo();
        
        // Property: Key duo must provide access to signing key pair
        expect(keyDuo.signing, isNotNull,
               reason: 'Key duo must provide signing key pair');
        expect(keyDuo.signing.privateKey, isNotNull,
               reason: 'Signing key pair must have private key');
        expect(keyDuo.signing.publicKey, isNotNull,
               reason: 'Signing key pair must have public key');
        
        // Property: Key duo must provide access to encryption key pair
        expect(keyDuo.encryption, isNotNull,
               reason: 'Key duo must provide encryption key pair');
        expect(keyDuo.encryption.privateKey, isNotNull,
               reason: 'Encryption key pair must have private key');
        expect(keyDuo.encryption.publicKey, isNotNull,
               reason: 'Encryption key pair must have public key');
        
        // Property: Both key pairs must be functional (can export)
        final ExportedJwk signingPrivateExport = await keyDuo.signing.exportPrivateKey();
        final ExportedJwk signingPublicExport = await keyDuo.signing.exportPublicKey();
        final ExportedJwk encryptionPrivateExport = await keyDuo.encryption.exportPrivateKey();
        final ExportedJwk encryptionPublicExport = await keyDuo.encryption.exportPublicKey();
        
        expect(signingPrivateExport, isNotNull,
               reason: 'Signing key pair must be able to export private key');
        expect(signingPublicExport, isNotNull,
               reason: 'Signing key pair must be able to export public key');
        expect(encryptionPrivateExport, isNotNull,
               reason: 'Encryption key pair must be able to export private key');
        expect(encryptionPublicExport, isNotNull,
               reason: 'Encryption key pair must be able to export public key');
        
        // Property: Key pairs must have consistent key IDs between private and public exports
        expect(signingPrivateExport.keyId, equals(signingPublicExport.keyId),
               reason: 'Signing private and public exports must have same key ID');
        expect(encryptionPrivateExport.keyId, equals(encryptionPublicExport.keyId),
               reason: 'Encryption private and public exports must have same key ID');
        
        // Property: Key pairs must be independently accessible (different instances)
        expect(identical(keyDuo.signing, keyDuo.encryption), isFalse,
               reason: 'Signing and encryption key pairs must be different instances');
        
        // Property: Key IDs must be calculable independently
        final String signingKeyId = await keyDuo.signing.calculateKeyId();
        final String encryptionKeyId = await keyDuo.encryption.calculateKeyId();
        
        expect(signingKeyId, isNotEmpty,
               reason: 'Signing key ID must be calculable');
        expect(encryptionKeyId, isNotEmpty,
               reason: 'Encryption key ID must be calculable');
        expect(signingKeyId, isNot(equals(encryptionKeyId)),
               reason: 'Signing and encryption key IDs must be different');
      }
    });
  });

  group('KeyDuoSerializer', () {
    /// **Feature: jwk-duo, Property 6: JWK Set export structure**
    /// **Validates: Requirements 3.1**
    test('property test - JWK Set export structure', () async {
      final generator = KeyDuoGenerator(modulusLength: RsaParameters.modulusLength);
      
      // Run property test with expensive iterations (key generation is slow)
      for (int i = 0; i < expensiveIterations; i++) {
        // Generate a random key duo
        final keyDuo = await generator.generateKeyDuo();
        final serializer = KeyDuoSerializer();
        
        // Export as JWK Set
        final jwkSetJson = await serializer.exportKeyDuo(keyDuo);
        final jwkSetData = jsonDecode(jwkSetJson) as Map<String, dynamic>;
        
        // Property: JWK Set must contain "keys" array
        expect(jwkSetData.containsKey('keys'), isTrue,
               reason: 'JWK Set must contain "keys" array');
        
        final keys = jwkSetData['keys'] as List;
        
        // Property: JWK Set must contain exactly 2 keys
        expect(keys.length, equals(2),
               reason: 'JWK Set must contain exactly 2 keys');
        
        // Property: Each key must be a valid object
        for (final key in keys) {
          expect(key, isA<Map<String, dynamic>>(),
                 reason: 'Each key in JWK Set must be an object');
          
          final keyMap = key as Map<String, dynamic>;
          
          // Property: Each key must have required metadata
          expect(keyMap.containsKey('kid'), isTrue,
                 reason: 'Each key must have key identifier');
          expect(keyMap.containsKey('alg'), isTrue,
                 reason: 'Each key must have algorithm');
          expect(keyMap.containsKey('use'), isTrue,
                 reason: 'Each key must have use field');
          expect(keyMap.containsKey('kty'), isTrue,
                 reason: 'Each key must have key type');
        }
        
        // Property: Must contain one signing key and one encryption key
        final uses = keys.map((k) => (k as Map<String, dynamic>)['use']).toSet();
        expect(uses.contains('sig'), isTrue,
               reason: 'JWK Set must contain a signing key');
        expect(uses.contains('enc'), isTrue,
               reason: 'JWK Set must contain an encryption key');
      }
    });

    /// **Feature: jwk-duo, Property 7: Private key export completeness**
    /// **Validates: Requirements 3.4, 3.5**
    test('property test - Private key export completeness', () async {
      final generator = KeyDuoGenerator(modulusLength: RsaParameters.modulusLength);
      
      // Run property test with expensive iterations
      for (int i = 0; i < expensiveIterations; i++) {
        final keyDuo = await generator.generateKeyDuo();
        final serializer = KeyDuoSerializer();
        
        // Export private keys
        final jwkSetJson = await serializer.exportKeyDuo(keyDuo);
        final jwkSetData = jsonDecode(jwkSetJson) as Map<String, dynamic>;
        final keys = jwkSetData['keys'] as List;
        
        for (final key in keys) {
          final keyMap = key as Map<String, dynamic>;
          
          // Property: Private key export must contain all required RSA parameters
          expect(keyMap['kty'], equals('RSA'),
                 reason: 'Key type must be RSA');
          expect(keyMap.containsKey('n'), isTrue,
                 reason: 'RSA key must contain modulus "n"');
          expect(keyMap.containsKey('e'), isTrue,
                 reason: 'RSA key must contain public exponent "e"');
          expect(keyMap.containsKey('d'), isTrue,
                 reason: 'Private key must contain private exponent "d"');
          
          // Property: Private exponent must not be empty
          expect(keyMap['d'], isNotEmpty,
                 reason: 'Private exponent must not be empty');
          
          // Property: Algorithm and use must be consistent
          final alg = keyMap['alg'] as String;
          final use = keyMap['use'] as String;
          
          if (use == 'sig') {
            expect(alg, equals('PS256'),
                   reason: 'Signing key must have PS256 algorithm');
          } else if (use == 'enc') {
            expect(alg, equals('RSA-OAEP-256'),
                   reason: 'Encryption key must have RSA-OAEP-256 algorithm');
          }
        }
      }
    });

    /// **Feature: jwk-duo, Property 8: JWK Set import validation**
    /// **Validates: Requirements 4.1, 4.2, 4.3**
    test('property test - JWK Set import validation', () async {
      final generator = KeyDuoGenerator(modulusLength: RsaParameters.modulusLength);
      final serializer = KeyDuoSerializer();
      
      // Run property test with expensive iterations
      for (int i = 0; i < expensiveIterations; i++) {
        // Generate and export a key duo
        final originalKeyDuo = await generator.generateKeyDuo();
        final jwkSetJson = await serializer.exportKeyDuo(originalKeyDuo);
        
        // Property: Valid JWK Set should import successfully
        final importedKeyDuo = await serializer.importKeyDuo(jwkSetJson);
        
        // Property: Imported key duo should have correct structure
        expect(importedKeyDuo, isA<IKeyDuo>(),
               reason: 'Import should return IKeyDuo instance');
        expect(importedKeyDuo.signing, isNotNull,
               reason: 'Imported key duo must have signing key pair');
        expect(importedKeyDuo.encryption, isNotNull,
               reason: 'Imported key duo must have encryption key pair');
        
        // Property: Imported keys should have correct types
        expect(importedKeyDuo.signing.privateKey, isA<RsaPssPrivateKey>(),
               reason: 'Signing private key must be RSA-PSS type');
        expect(importedKeyDuo.signing.publicKey, isA<RsaPssPublicKey>(),
               reason: 'Signing public key must be RSA-PSS type');
        expect(importedKeyDuo.encryption.privateKey, isA<RsaOaepPrivateKey>(),
               reason: 'Encryption private key must be RSA-OAEP type');
        expect(importedKeyDuo.encryption.publicKey, isA<RsaOaepPublicKey>(),
               reason: 'Encryption public key must be RSA-OAEP type');
      }
    });

    /// **Feature: jwk-duo, Property 9: Import key validation**
    /// **Validates: Requirements 4.4**
    test('property test - Import key validation', () async {
      final serializer = KeyDuoSerializer();
      
      // Test invalid JWK Set structures
      final invalidJwkSets = [
        '{}', // Missing keys array
        '{"keys": []}', // Empty keys array
        '{"keys": [{}]}', // Single key (need 2)
        '{"keys": [{}, {}, {}]}', // Too many keys
        '{"keys": [{"use": "sig"}, {"use": "invalid"}]}', // Invalid use
        '{"keys": [{"use": "sig", "kty": "EC"}, {"use": "enc", "kty": "RSA"}]}', // Wrong key type
        '{"keys": [{"use": "sig", "kty": "RSA"}, {"use": "enc", "kty": "RSA"}]}', // Missing required fields
      ];
      
      for (final invalidJwkSet in invalidJwkSets) {
        // Property: Invalid JWK Sets should throw FormatException
        expect(
          () => serializer.importKeyDuo(invalidJwkSet),
          throwsA(isA<FormatException>()),
          reason: 'Invalid JWK Set should throw FormatException: $invalidJwkSet',
        );
      }
      
      // Test malformed JSON
      expect(
        () => serializer.importKeyDuo('invalid json'),
        throwsA(isA<FormatException>()),
        reason: 'Malformed JSON should throw FormatException',
      );
    });

    /// **Feature: jwk-duo, Property 10: Import-export round trip**
    /// **Validates: Requirements 4.5**
    test('property test - Import-export round trip', () async {
      final generator = KeyDuoGenerator(modulusLength: RsaParameters.modulusLength);
      final serializer = KeyDuoSerializer();
      
      // Run property test with expensive iterations
      for (int i = 0; i < expensiveIterations; i++) {
        // Generate original key duo
        final originalKeyDuo = await generator.generateKeyDuo();
        
        // Export to JWK Set
        final jwkSetJson = await serializer.exportKeyDuo(originalKeyDuo);
        
        // Import back to KeyDuo
        final importedKeyDuo = await serializer.importKeyDuo(jwkSetJson);
        
        // Export again to verify consistency
        final reExportedJson = await serializer.exportKeyDuo(importedKeyDuo);
        
        // Property: Round-trip should preserve key structure
        final originalData = jsonDecode(jwkSetJson) as Map<String, dynamic>;
        final reExportedData = jsonDecode(reExportedJson) as Map<String, dynamic>;
        
        // Compare key structure (not exact equality due to potential ordering differences)
        final originalKeys = originalData['keys'] as List;
        final reExportedKeys = reExportedData['keys'] as List;
        
        expect(originalKeys.length, equals(reExportedKeys.length),
               reason: 'Round-trip should preserve number of keys');
        
        // Verify both key sets contain the same key identifiers
        final originalKids = originalKeys.map((k) => (k as Map<String, dynamic>)['kid']).toSet();
        final reExportedKids = reExportedKeys.map((k) => (k as Map<String, dynamic>)['kid']).toSet();
        
        expect(originalKids, equals(reExportedKids),
               reason: 'Round-trip should preserve key identifiers');
        
        // Property: Imported keys should be functional
        final signingExport = await importedKeyDuo.signing.exportPrivateKey();
        final encryptionExport = await importedKeyDuo.encryption.exportPrivateKey();
        
        expect(signingExport.alg, equals('PS256'),
               reason: 'Imported signing key should have correct algorithm');
        expect(encryptionExport.alg, equals('RSA-OAEP-256'),
               reason: 'Imported encryption key should have correct algorithm');
      }
    });
  });

  group('Configuration and Validation', () {
    /// **Feature: jwk-duo, Property 14: Thumbprint validation**
    /// **Validates: Requirements 5.4, 5.5**
    test('property test - Thumbprint validation', () async {
      // Run property test with expensive iterations (RSA key generation is expensive)
      for (int i = 0; i < expensiveIterations; i++) {
        // Generate key pairs with the configuration
        final KeyDuoGenerator generator = KeyDuoGenerator(
          modulusLength: RsaParameters.modulusLength,
        );
        final IKeyDuo keyDuo = await generator.generateKeyDuo();
        
        // Test signing key thumbprint validation
        final ExportedJwk signingExport = await keyDuo.signing.exportPrivateKey();
        final Map<String, dynamic> signingJson = signingExport.toJson();
        
        // Property: The 'kid' field should be based on RFC 7638 thumbprint
        final String expectedSigningThumbprint = await calculateJwkThumbprint({
          'kty': signingJson['kty'],
          'n': signingJson['n'],
          'e': signingJson['e'],
        });
        
        // Check if the kid matches the expected RFC 7638 thumbprint
        expect(signingExport.keyId, equals(expectedSigningThumbprint),
               reason: 'Signing key ID should be RFC 7638 thumbprint');
        
        // Test encryption key thumbprint validation
        final ExportedJwk encryptionExport = await keyDuo.encryption.exportPrivateKey();
        final Map<String, dynamic> encryptionJson = encryptionExport.toJson();
        
        // Property: The 'kid' field should be based on RFC 7638 thumbprint
        final String expectedEncryptionThumbprint = await calculateJwkThumbprint({
          'kty': encryptionJson['kty'],
          'n': encryptionJson['n'],
          'e': encryptionJson['e'],
        });
        
        // Check if the kid matches the expected RFC 7638 thumbprint
        expect(encryptionExport.keyId, equals(expectedEncryptionThumbprint),
               reason: 'Encryption key ID should be RFC 7638 thumbprint');
        
        // Property: Public key exports should have same kid as private key exports
        final ExportedJwk signingPublicExport = await keyDuo.signing.exportPublicKey();
        final ExportedJwk encryptionPublicExport = await keyDuo.encryption.exportPublicKey();
        
        expect(signingPublicExport.keyId, equals(signingExport.keyId),
               reason: 'Signing public key should have same kid as private key');
        expect(encryptionPublicExport.keyId, equals(encryptionExport.keyId),
               reason: 'Encryption public key should have same kid as private key');
        
        // Property: Thumbprint should be consistent across multiple calculations
        final String signingKeyId1 = await keyDuo.signing.calculateKeyId();
        final String signingKeyId2 = await keyDuo.signing.calculateKeyId();
        final String encryptionKeyId1 = await keyDuo.encryption.calculateKeyId();
        final String encryptionKeyId2 = await keyDuo.encryption.calculateKeyId();
        
        expect(signingKeyId1, equals(signingKeyId2),
               reason: 'Signing key ID calculation should be consistent');
        expect(encryptionKeyId1, equals(encryptionKeyId2),
               reason: 'Encryption key ID calculation should be consistent');
        
        // Property: Calculated key IDs should match export kid values
        expect(signingExport.keyId, equals(signingKeyId1),
               reason: 'Signing export kid should match calculated key ID');
        expect(encryptionExport.keyId, equals(encryptionKeyId1),
               reason: 'Encryption export kid should match calculated key ID');
        
        // Property: Configuration should be applied consistently across serialization
        final KeyDuoSerializer serializer = KeyDuoSerializer();
        final String jwkSetJson = await serializer.exportKeyDuo(keyDuo);
        final IKeyDuo importedKeyDuo = await serializer.importKeyDuo(jwkSetJson);
        
        // Verify that imported keys maintain the same key IDs
        final ExportedJwk importedSigningExport = await importedKeyDuo.signing.exportPrivateKey();
        final ExportedJwk importedEncryptionExport = await importedKeyDuo.encryption.exportPrivateKey();
        
        expect(importedSigningExport.keyId, equals(signingExport.keyId),
               reason: 'Imported signing key should maintain same kid');
        expect(importedEncryptionExport.keyId, equals(encryptionExport.keyId),
               reason: 'Imported encryption key should maintain same kid');
      }
    });
  });
}

/// Generates a random RSA JWK for testing
Map<String, dynamic> _generateRandomRsaJwk(Random random) {
  // Generate random base64url strings for RSA parameters
  final n = _generateRandomBase64Url(random, 256); // 2048-bit modulus
  final e = 'AQAB'; // Standard public exponent (65537)
  
  return {
    'kty': 'RSA',
    'n': n,
    'e': e,
  };
}

/// Generates a random base64url string of specified byte length
String _generateRandomBase64Url(Random random, int byteLength) {
  final bytes = List<int>.generate(byteLength, (_) => random.nextInt(256));
  // Use proper base64 encoding and convert to base64url format
  final base64 = base64Encode(bytes);
  // Convert to base64url format (RFC 4648 Section 5)
  return base64.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

/// Generates a valid RSA JWK with all required and optional components
Map<String, dynamic> _generateValidRsaJwkData(Random random, {bool includePrivate = false}) {
  // Generate random base64url strings for RSA parameters
  final String n = _generateRandomBase64Url(random, 256); // 2048-bit modulus
  const String e = 'AQAB'; // Standard public exponent (65537)
  
  final Map<String, dynamic> jwk = <String, dynamic>{
    'kty': JwkKeyType.rsa,
    'n': n,
    'e': e,
  };
  
  if (includePrivate) {
    // Add private RSA components for testing
    jwk['d'] = _generateRandomBase64Url(random, 256); // Private exponent
    jwk['p'] = _generateRandomBase64Url(random, 128); // First prime factor
    jwk['q'] = _generateRandomBase64Url(random, 128); // Second prime factor
    jwk['dp'] = _generateRandomBase64Url(random, 128); // First factor CRT exponent
    jwk['dq'] = _generateRandomBase64Url(random, 128); // Second factor CRT exponent
    jwk['qi'] = _generateRandomBase64Url(random, 128); // First CRT coefficient
  }
  
  return jwk;
}

/// Checks if two JWKs are equal for the thumbprint calculation
bool _areJwksEqual(Map<String, dynamic> jwk1, Map<String, dynamic> jwk2) {
  return jwk1['kty'] == jwk2['kty'] &&
         jwk1['n'] == jwk2['n'] &&
         jwk1['e'] == jwk2['e'];
}