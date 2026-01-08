import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dart_jwk_duo/src/jwk_thumbprint.dart';
import 'package:dart_jwk_duo/src/exported_jwk.dart';
import 'package:dart_jwk_duo/src/constants.dart';
import 'package:dart_jwk_duo/src/signing_key_pair.dart';
import 'package:dart_jwk_duo/src/encryption_key_pair.dart';
import 'package:dart_jwk_duo/src/key_duo.dart';
import 'package:dart_jwk_duo/src/generation_service.dart';
import 'package:dart_jwk_duo/src/verification_service.dart';
import 'package:dart_jwk_duo/src/key_duo_serializer.dart';
import 'package:dart_jwk_duo/src/interfaces.dart';
import 'package:webcrypto/webcrypto.dart';

// Property-based test iteration counts
const int lightweightIterations = 3; // For fast operations (hashing, object creation)
const int expensiveIterations = 1;   // For slow operations (key generation) - keep minimal

void main() {
  group('Dart JWK Duo', () {
    test('placeholder test', () {
      expect(true, isTrue);
    });
  });

  group('JWK Thumbprint (EC only)', () {
    test('property test - JWK thumbprint consistency', () async {
      final Random random = Random();
      
      for (int i = 0; i < lightweightIterations; i++) {
        final Map<String, dynamic> jwk = _generateRandomEcJwk(random);
        
        final String thumbprint1 = await calculateJwkThumbprint(jwk);
        final String thumbprint2 = await calculateJwkThumbprint(jwk);
        
        expect(thumbprint1, equals(thumbprint2),
               reason: 'Thumbprint should be consistent for the same JWK');
        expect(thumbprint1, matches(RegExp(r'^[A-Za-z0-9_-]+$')),
               reason: 'Thumbprint should be valid base64url without padding');
        expect(thumbprint1.length, equals(43),
               reason: 'SHA-256 thumbprint should be 43 characters');
      }
    });

    test('JWK thumbprint validation errors', () async {
      expect(
        () => calculateJwkThumbprint({'kty': 'EC', 'crv': 'P-256', 'x': 'test'}),
        throwsA(isA<ArgumentError>()),
        reason: 'Should throw when missing required field "y"',
      );
    });
  });


  group('ExportedJwk DTO', () {
    test('property test - EC signing key DTO', () async {
      final Random random = Random();
      
      for (int i = 0; i < lightweightIterations; i++) {
        final Map<String, dynamic> ecJwkData = _generateValidEcJwkData(random);
        final String signingKid = 'test-signing-${random.nextInt(1000)}';
        
        final ExportedJwk signingExport = ExportedJwk(
          keyData: ecJwkData,
          keyId: signingKid,
          alg: JwkAlgorithm.es256,
          use: JwkUse.signature,
        );
        
        expect(signingExport.keyId, equals(signingKid));
        expect(signingExport.alg, equals(JwkAlgorithm.es256));
        expect(signingExport.use, equals(JwkUse.signature));
        
        final Map<String, dynamic> signingJson = signingExport.toJson();
        expect(signingJson['kid'], equals(signingKid));
        expect(signingJson['alg'], equals(JwkAlgorithm.es256));
        expect(signingJson['use'], equals(JwkUse.signature));
        expect(signingJson['kty'], equals(JwkKeyType.ec));
      }
    });

    test('property test - ECDH encryption key DTO', () async {
      final Random random = Random();
      
      for (int i = 0; i < lightweightIterations; i++) {
        final Map<String, dynamic> ecdhJwkData = _generateValidEcJwkData(random);
        final String encryptionKid = 'test-encryption-${random.nextInt(1000)}';
        
        final ExportedJwk encryptionExport = ExportedJwk(
          keyData: ecdhJwkData,
          keyId: encryptionKid,
          alg: JwkAlgorithm.ecdhEs256,
          use: JwkUse.encryption,
        );
        
        expect(encryptionExport.keyId, equals(encryptionKid));
        expect(encryptionExport.alg, equals(JwkAlgorithm.ecdhEs256));
        expect(encryptionExport.use, equals(JwkUse.encryption));
        
        final Map<String, dynamic> encryptionJson = encryptionExport.toJson();
        expect(encryptionJson['kid'], equals(encryptionKid));
        expect(encryptionJson['alg'], equals(JwkAlgorithm.ecdhEs256));
        expect(encryptionJson['use'], equals(JwkUse.encryption));
        expect(encryptionJson['kty'], equals(JwkKeyType.ec));
      }
    });

    test('ExportedJwk validation errors', () {
      final Map<String, dynamic> ecJwkData = _generateValidEcJwkData(Random());
      final Map<String, dynamic> ecdhJwkData = _generateValidEcJwkData(Random());
      
      // ES256 with wrong use
      expect(
        () => ExportedJwk(
          keyData: ecJwkData,
          keyId: 'test',
          alg: JwkAlgorithm.es256,
          use: JwkUse.encryption,
        ),
        throwsA(isA<ArgumentError>()),
        reason: 'Should throw for ES256 with encryption use',
      );
      
      // ECDH-ES+A256KW with wrong use
      expect(
        () => ExportedJwk(
          keyData: ecdhJwkData,
          keyId: 'test',
          alg: JwkAlgorithm.ecdhEs256,
          use: JwkUse.signature,
        ),
        throwsA(isA<ArgumentError>()),
        reason: 'Should throw for ECDH-ES+A256KW with signature use',
      );
    });

    test('property test - EC public key export safety', () async {
      final Random random = Random();
      
      for (int i = 0; i < lightweightIterations; i++) {
        final Map<String, dynamic> privateEcJwkData = _generateValidEcJwkData(random, includePrivate: true);
        
        final ExportedJwk privateExport = ExportedJwk(
          keyData: privateEcJwkData,
          keyId: 'test-${random.nextInt(1000)}',
          alg: JwkAlgorithm.es256,
          use: JwkUse.signature,
        );
        
        final ExportedJwk publicExport = privateExport.toPublicOnly();
        final Map<String, dynamic> publicJson = publicExport.toJson();
        
        // Must NOT contain private component
        expect(publicJson.containsKey('d'), isFalse,
               reason: 'Public key must not contain private component d');
        
        // Must preserve public components
        expect(publicJson['kty'], equals(JwkKeyType.ec));
        expect(publicJson['crv'], equals(privateEcJwkData['crv']));
        expect(publicJson['x'], equals(privateEcJwkData['x']));
        expect(publicJson['y'], equals(privateEcJwkData['y']));
        expect(publicJson['kid'], equals(privateExport.keyId));
        expect(publicJson['alg'], equals(privateExport.alg));
        expect(publicJson['use'], equals(privateExport.use));
      }
    });
  });


  group('SigningKeyPair (ECDSA P-256)', () {
    test('property test - Signing key export includes correct metadata', () async {
      for (int i = 0; i < expensiveIterations; i++) {
        // Generate ECDSA P-256 key pair
        final ({EcdsaPrivateKey privateKey, EcdsaPublicKey publicKey}) keyPair =
            await EcdsaPrivateKey.generateKey(EllipticCurve.p256);
        
        final SigningKeyPair signingKeyPair = SigningKeyPair(
          privateKey: keyPair.privateKey,
          publicKey: keyPair.publicKey,
        );
        
        // Test private key export
        final ExportedJwk privateExport = await signingKeyPair.exportPrivateKey();
        
        expect(privateExport.alg, equals(JwkAlgorithm.es256),
               reason: 'Signing key must have ES256 algorithm');
        expect(privateExport.use, equals(JwkUse.signature),
               reason: 'Signing key must have signature use');
        expect(privateExport.keyId, isNotEmpty,
               reason: 'Key ID must not be empty');
        expect(privateExport.keyId, matches(RegExp(r'^[A-Za-z0-9_-]+$')),
               reason: 'Key ID should be valid base64url format');
        
        // Key ID consistency
        final String keyId1 = await signingKeyPair.calculateKeyId();
        final String keyId2 = await signingKeyPair.calculateKeyId();
        expect(keyId1, equals(keyId2),
               reason: 'Key ID should be consistent across calculations');
        expect(privateExport.keyId, equals(keyId1),
               reason: 'Export kid should match calculated key ID');
        
        // Test public key export
        final ExportedJwk publicExport = await signingKeyPair.exportPublicKey();
        
        expect(publicExport.alg, equals(JwkAlgorithm.es256),
               reason: 'Public key must have same algorithm as private');
        expect(publicExport.use, equals(JwkUse.signature),
               reason: 'Public key must have same use as private');
        expect(publicExport.keyId, equals(privateExport.keyId),
               reason: 'Public key must have same kid as private');
        
        // Exported JSON metadata
        final Map<String, dynamic> privateJson = privateExport.toJson();
        expect(privateJson['alg'], equals(JwkAlgorithm.es256));
        expect(privateJson['use'], equals(JwkUse.signature));
        expect(privateJson['kid'], equals(privateExport.keyId));
        expect(privateJson['kty'], equals(JwkKeyType.ec));
        expect(privateJson['crv'], equals(JwkCurve.p256));
        
        final Map<String, dynamic> publicJson = publicExport.toJson();
        expect(publicJson['alg'], equals(JwkAlgorithm.es256));
        expect(publicJson['use'], equals(JwkUse.signature));
        expect(publicJson['kid'], equals(publicExport.keyId));
        expect(publicJson['kty'], equals(JwkKeyType.ec));
        expect(publicJson.containsKey('d'), isFalse,
               reason: 'Public key export must not contain private component');
      }
    });

    test('property test - Signing key pair validation', () async {
      for (int i = 0; i < expensiveIterations; i++) {
        final ({EcdsaPrivateKey privateKey, EcdsaPublicKey publicKey}) keyPair =
            await EcdsaPrivateKey.generateKey(EllipticCurve.p256);
        
        final SigningKeyPair signingKeyPair = SigningKeyPair(
          privateKey: keyPair.privateKey,
          publicKey: keyPair.publicKey,
        );
        
        final bool isValid = await VerificationService.verifySigningKeyPair(signingKeyPair);
        expect(isValid, isTrue,
               reason: 'Properly paired keys should validate successfully');
        
        // Public-only key pair validation
        final SigningKeyPair publicOnlyKeyPair = SigningKeyPair.publicOnly(
          publicKey: keyPair.publicKey,
        );
        
        expect(
          () => VerificationService.verifySigningKeyPair(publicOnlyKeyPair),
          throwsA(isA<StateError>()),
          reason: 'Public-only key pair should throw StateError on validation',
        );
      }
    });

    test('property test - Sign and verify operations', () async {
      for (int i = 0; i < expensiveIterations; i++) {
        final ({EcdsaPrivateKey privateKey, EcdsaPublicKey publicKey}) keyPair =
            await EcdsaPrivateKey.generateKey(EllipticCurve.p256);
        
        final SigningKeyPair signingKeyPair = SigningKeyPair(
          privateKey: keyPair.privateKey,
          publicKey: keyPair.publicKey,
        );
        
        // Sign a message
        final Uint8List message = Uint8List.fromList('test message $i'.codeUnits);
        final Uint8List signature = await signingKeyPair.signBytes(message);
        
        // Verify signature
        final bool isValid = await signingKeyPair.verifyBytes(signature, message);
        expect(isValid, isTrue, reason: 'Signature should verify correctly');
        
        // Verify with wrong message should fail
        final Uint8List wrongMessage = Uint8List.fromList('wrong message'.codeUnits);
        final bool isInvalid = await signingKeyPair.verifyBytes(signature, wrongMessage);
        expect(isInvalid, isFalse, reason: 'Signature should not verify with wrong message');
      }
    });

    test('property test - Export public key as hex', () async {
      for (int i = 0; i < expensiveIterations; i++) {
        final ({EcdsaPrivateKey privateKey, EcdsaPublicKey publicKey}) keyPair =
            await EcdsaPrivateKey.generateKey(EllipticCurve.p256);
        
        final SigningKeyPair signingKeyPair = SigningKeyPair(
          privateKey: keyPair.privateKey,
          publicKey: keyPair.publicKey,
        );
        
        final String publicKeyHex = await signingKeyPair.exportPublicKeyHex();
        
        // ECDSA P-256 public key should be 128 hex chars (64 bytes = x||y)
        expect(publicKeyHex.length, equals(128),
               reason: 'Public key hex should be 128 characters');
        expect(publicKeyHex, matches(RegExp(r'^[0-9a-f]+$')),
               reason: 'Public key hex should be lowercase hex');
        
        // Raw export should be 65 bytes (04 prefix + 64 bytes)
        final Uint8List publicKeyRaw = await signingKeyPair.exportPublicKeyRaw();
        expect(publicKeyRaw.length, equals(65),
               reason: 'Raw public key should be 65 bytes (with 04 prefix)');
        expect(publicKeyRaw[0], equals(0x04),
               reason: 'Raw public key should start with 04 prefix');
      }
    });
  });


  group('EncryptionKeyPair (ECDH P-256)', () {
    test('property test - Encryption key export includes correct metadata', () async {
      for (int i = 0; i < expensiveIterations; i++) {
        final ({EcdhPrivateKey privateKey, EcdhPublicKey publicKey}) keyPair =
            await EcdhPrivateKey.generateKey(EllipticCurve.p256);
        
        final EncryptionKeyPair encryptionKeyPair = EncryptionKeyPair(
          privateKey: keyPair.privateKey,
          publicKey: keyPair.publicKey,
        );
        
        final ExportedJwk privateExport = await encryptionKeyPair.exportPrivateKey();
        
        expect(privateExport.alg, equals(JwkAlgorithm.ecdhEs256),
               reason: 'Encryption key must have ECDH-ES+A256KW algorithm');
        expect(privateExport.use, equals(JwkUse.encryption),
               reason: 'Encryption key must have encryption use');
        expect(privateExport.keyId, isNotEmpty,
               reason: 'Key ID must not be empty');
        
        final String keyId1 = await encryptionKeyPair.calculateKeyId();
        final String keyId2 = await encryptionKeyPair.calculateKeyId();
        expect(keyId1, equals(keyId2),
               reason: 'Key ID should be consistent across calculations');
        
        final ExportedJwk publicExport = await encryptionKeyPair.exportPublicKey();
        
        expect(publicExport.alg, equals(JwkAlgorithm.ecdhEs256));
        expect(publicExport.use, equals(JwkUse.encryption));
        expect(publicExport.keyId, equals(privateExport.keyId));
        
        final Map<String, dynamic> privateJson = privateExport.toJson();
        expect(privateJson['kty'], equals(JwkKeyType.ec));
        expect(privateJson.containsKey('d'), isTrue,
               reason: 'Private key must contain private component');
        
        final Map<String, dynamic> publicJson = publicExport.toJson();
        expect(publicJson['kty'], equals(JwkKeyType.ec));
        expect(publicJson.containsKey('d'), isFalse,
               reason: 'Public key must not contain private component');
      }
    });

    test('property test - Encryption key pair validation', () async {
      for (int i = 0; i < expensiveIterations; i++) {
        final ({EcdhPrivateKey privateKey, EcdhPublicKey publicKey}) keyPair =
            await EcdhPrivateKey.generateKey(EllipticCurve.p256);
        
        final EncryptionKeyPair encryptionKeyPair = EncryptionKeyPair(
          privateKey: keyPair.privateKey,
          publicKey: keyPair.publicKey,
        );
        
        final bool isValid = await VerificationService.verifyEncryptionKeyPair(encryptionKeyPair);
        expect(isValid, isTrue,
               reason: 'Properly paired keys should validate successfully');
        
        final EncryptionKeyPair publicOnlyKeyPair = EncryptionKeyPair.publicOnly(
          publicKey: keyPair.publicKey,
        );
        
        expect(
          () => VerificationService.verifyEncryptionKeyPair(publicOnlyKeyPair),
          throwsA(isA<StateError>()),
          reason: 'Public-only key pair should throw StateError on validation',
        );
      }
    });
  });


  group('KeyDuo and GenerationService', () {
    test('property test - Key generation produces correct key types', () async {
      for (int i = 0; i < expensiveIterations; i++) {
        final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
        
        // Signing key must be ECDSA P-256
        expect(keyDuo.signing, isA<IKeyPair<EcdsaPrivateKey?, EcdsaPublicKey>>(),
               reason: 'Signing key pair must have ECDSA types');
        expect(keyDuo.signing.privateKey, isA<EcdsaPrivateKey>(),
               reason: 'Signing private key must be ECDSA type');
        expect(keyDuo.signing.publicKey, isA<EcdsaPublicKey>(),
               reason: 'Signing public key must be ECDSA type');
        
        // Encryption key must be ECDH P-256
        expect(keyDuo.encryption, isA<IKeyPair<EcdhPrivateKey?, EcdhPublicKey>>(),
               reason: 'Encryption key pair must have ECDH types');
        expect(keyDuo.encryption.privateKey, isA<EcdhPrivateKey>(),
               reason: 'Encryption private key must be ECDH type');
        expect(keyDuo.encryption.publicKey, isA<EcdhPublicKey>(),
               reason: 'Encryption public key must be ECDH type');
        
        // Signing key metadata
        final ExportedJwk signingExport = await keyDuo.signing.exportPrivateKey();
        expect(signingExport.alg, equals(JwkAlgorithm.es256),
               reason: 'Signing key must have ES256 algorithm');
        expect(signingExport.use, equals(JwkUse.signature),
               reason: 'Signing key must have signature use');
        
        // Encryption key metadata
        final ExportedJwk encryptionExport = await keyDuo.encryption.exportPrivateKey();
        expect(encryptionExport.alg, equals(JwkAlgorithm.ecdhEs256),
               reason: 'Encryption key must have ECDH-ES+A256KW algorithm');
        expect(encryptionExport.use, equals(JwkUse.encryption),
               reason: 'Encryption key must have encryption use');
        
        // Keys must be different
        expect(signingExport.keyId, isNot(equals(encryptionExport.keyId)),
               reason: 'Signing and encryption keys must have different key IDs');
      }
    });

    test('property test - Key generation uses correct cryptographic parameters', () async {
      for (int i = 0; i < expensiveIterations; i++) {
        final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
        
        final ExportedJwk signingExport = await keyDuo.signing.exportPrivateKey();
        final ExportedJwk encryptionExport = await keyDuo.encryption.exportPrivateKey();
        
        final Map<String, dynamic> signingJson = signingExport.toJson();
        final Map<String, dynamic> encryptionJson = encryptionExport.toJson();
        
        // Signing key must be EC with P-256 curve
        expect(signingJson['kty'], equals(JwkKeyType.ec),
               reason: 'Signing key must use EC key type');
        expect(signingJson['crv'], equals(JwkCurve.p256),
               reason: 'Signing key must use P-256 curve');
        expect(signingJson.containsKey('x'), isTrue,
               reason: 'EC key must contain x coordinate');
        expect(signingJson.containsKey('y'), isTrue,
               reason: 'EC key must contain y coordinate');
        expect(signingJson.containsKey('d'), isTrue,
               reason: 'Private EC key must contain d component');
        
        // Encryption key must be EC with P-256 curve (ECDH)
        expect(encryptionJson['kty'], equals(JwkKeyType.ec),
               reason: 'Encryption key must use EC key type');
        expect(encryptionJson['crv'], equals(JwkCurve.p256),
               reason: 'Encryption key must use P-256 curve');
        expect(encryptionJson.containsKey('x'), isTrue,
               reason: 'EC key must contain x coordinate');
        expect(encryptionJson.containsKey('y'), isTrue,
               reason: 'EC key must contain y coordinate');
        expect(encryptionJson.containsKey('d'), isTrue,
               reason: 'Private EC key must contain d component');
      }
    });

    test('property test - Key duo contains both key pairs', () async {
      for (int i = 0; i < expensiveIterations; i++) {
        final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
        
        expect(keyDuo.signing, isNotNull,
               reason: 'Key duo must provide signing key pair');
        expect(keyDuo.signing.privateKey, isNotNull,
               reason: 'Signing key pair must have private key');
        expect(keyDuo.signing.publicKey, isNotNull,
               reason: 'Signing key pair must have public key');
        
        expect(keyDuo.encryption, isNotNull,
               reason: 'Key duo must provide encryption key pair');
        expect(keyDuo.encryption.privateKey, isNotNull,
               reason: 'Encryption key pair must have private key');
        expect(keyDuo.encryption.publicKey, isNotNull,
               reason: 'Encryption key pair must have public key');
        
        // Both key pairs must be functional
        final ExportedJwk signingPrivateExport = await keyDuo.signing.exportPrivateKey();
        final ExportedJwk signingPublicExport = await keyDuo.signing.exportPublicKey();
        final ExportedJwk encryptionPrivateExport = await keyDuo.encryption.exportPrivateKey();
        final ExportedJwk encryptionPublicExport = await keyDuo.encryption.exportPublicKey();
        
        expect(signingPrivateExport, isNotNull);
        expect(signingPublicExport, isNotNull);
        expect(encryptionPrivateExport, isNotNull);
        expect(encryptionPublicExport, isNotNull);
        
        // Key IDs must be consistent
        expect(signingPrivateExport.keyId, equals(signingPublicExport.keyId));
        expect(encryptionPrivateExport.keyId, equals(encryptionPublicExport.keyId));
        
        // Key pairs must be different instances
        expect(identical(keyDuo.signing, keyDuo.encryption), isFalse);
      }
    });

    test('property test - KeyDuo signingKeyPair accessor', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      
      // Access concrete SigningKeyPair for signing operations
      final SigningKeyPair signingKeyPair = keyDuo.signingKeyPair;
      
      // Should be able to sign and export hex
      final Uint8List message = Uint8List.fromList('test'.codeUnits);
      final Uint8List signature = await signingKeyPair.signBytes(message);
      expect(signature.length, equals(64), reason: 'ECDSA P-256 signature should be 64 bytes');
      
      final String publicKeyHex = await signingKeyPair.exportPublicKeyHex();
      expect(publicKeyHex.length, equals(128), reason: 'Public key hex should be 128 chars');
    });
  });


  group('KeyDuoSerializer', () {
    test('property test - JWK Set export structure', () async {
      
      for (int i = 0; i < expensiveIterations; i++) {
        final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
        final KeyDuoSerializer serializer = KeyDuoSerializer();
        
        final String jwkSetJson = await serializer.exportKeyDuo(keyDuo);
        final Map<String, dynamic> jwkSetData = jsonDecode(jwkSetJson) as Map<String, dynamic>;
        
        expect(jwkSetData.containsKey('keys'), isTrue,
               reason: 'JWK Set must contain "keys" array');
        
        final List<dynamic> keys = jwkSetData['keys'] as List<dynamic>;
        
        expect(keys.length, equals(2),
               reason: 'JWK Set must contain exactly 2 keys');
        
        for (final dynamic key in keys) {
          expect(key, isA<Map<String, dynamic>>(),
                 reason: 'Each key in JWK Set must be an object');
          
          final Map<String, dynamic> keyMap = key as Map<String, dynamic>;
          
          expect(keyMap.containsKey('kid'), isTrue,
                 reason: 'Each key must have key identifier');
          expect(keyMap.containsKey('alg'), isTrue,
                 reason: 'Each key must have algorithm');
          expect(keyMap.containsKey('use'), isTrue,
                 reason: 'Each key must have use field');
          expect(keyMap.containsKey('kty'), isTrue,
                 reason: 'Each key must have key type');
        }
        
        // Must contain one signing key (EC) and one encryption key (EC)
        final Set<String> uses = keys.map((k) => (k as Map<String, dynamic>)['use'] as String).toSet();
        expect(uses.contains('sig'), isTrue,
               reason: 'JWK Set must contain a signing key');
        expect(uses.contains('enc'), isTrue,
               reason: 'JWK Set must contain an encryption key');
        
        final Set<String> ktys = keys.map((k) => (k as Map<String, dynamic>)['kty'] as String).toSet();
        expect(ktys.contains('EC'), isTrue,
               reason: 'JWK Set must contain EC keys');
        expect(ktys.length, equals(1),
               reason: 'All keys should be EC type');
      }
    });

    test('property test - Private key export completeness', () async {
      
      for (int i = 0; i < expensiveIterations; i++) {
        final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
        final KeyDuoSerializer serializer = KeyDuoSerializer();
        
        final String jwkSetJson = await serializer.exportKeyDuo(keyDuo);
        final Map<String, dynamic> jwkSetData = jsonDecode(jwkSetJson) as Map<String, dynamic>;
        final List<dynamic> keys = jwkSetData['keys'] as List<dynamic>;
        
        for (final dynamic key in keys) {
          final Map<String, dynamic> keyMap = key as Map<String, dynamic>;
          final String use = keyMap['use'] as String;
          final String kty = keyMap['kty'] as String;
          
          if (use == 'sig') {
            // Signing key must be EC with ES256
            expect(kty, equals('EC'), reason: 'Signing key must be EC type');
            expect(keyMap['alg'], equals('ES256'), reason: 'Signing key must have ES256 algorithm');
            expect(keyMap['crv'], equals('P-256'), reason: 'Signing key must use P-256 curve');
            expect(keyMap.containsKey('x'), isTrue, reason: 'EC key must contain x coordinate');
            expect(keyMap.containsKey('y'), isTrue, reason: 'EC key must contain y coordinate');
            expect(keyMap.containsKey('d'), isTrue, reason: 'Private EC key must contain d component');
          } else if (use == 'enc') {
            // Encryption key must be EC with ECDH-ES+A256KW
            expect(kty, equals('EC'), reason: 'Encryption key must be EC type');
            expect(keyMap['alg'], equals('ECDH-ES+A256KW'), reason: 'Encryption key must have ECDH-ES+A256KW algorithm');
            expect(keyMap['crv'], equals('P-256'), reason: 'Encryption key must use P-256 curve');
            expect(keyMap.containsKey('x'), isTrue, reason: 'EC key must contain x coordinate');
            expect(keyMap.containsKey('y'), isTrue, reason: 'EC key must contain y coordinate');
            expect(keyMap.containsKey('d'), isTrue, reason: 'Private EC key must contain d component');
          }
        }
      }
    });

    test('property test - JWK Set import validation', () async {
      final KeyDuoSerializer serializer = KeyDuoSerializer();
      
      for (int i = 0; i < expensiveIterations; i++) {
        final KeyDuo originalKeyDuo = await GenerationService.generateKeyDuo();
        final String jwkSetJson = await serializer.exportKeyDuo(originalKeyDuo);
        
        final KeyDuo importedKeyDuo = await serializer.importKeyDuo(jwkSetJson);
        
        expect(importedKeyDuo, isA<KeyDuo>(),
               reason: 'Import should return IKeyDuo instance');
        expect(importedKeyDuo.signing, isNotNull,
               reason: 'Imported key duo must have signing key pair');
        expect(importedKeyDuo.encryption, isNotNull,
               reason: 'Imported key duo must have encryption key pair');
        
        // Imported keys should have correct types
        expect(importedKeyDuo.signing.privateKey, isA<EcdsaPrivateKey>(),
               reason: 'Signing private key must be ECDSA type');
        expect(importedKeyDuo.signing.publicKey, isA<EcdsaPublicKey>(),
               reason: 'Signing public key must be ECDSA type');
        expect(importedKeyDuo.encryption.privateKey, isA<EcdhPrivateKey>(),
               reason: 'Encryption private key must be ECDH type');
        expect(importedKeyDuo.encryption.publicKey, isA<EcdhPublicKey>(),
               reason: 'Encryption public key must be ECDH type');
      }
    });

    test('property test - Import key validation errors', () async {
      final KeyDuoSerializer serializer = KeyDuoSerializer();
      
      final List<String> invalidJwkSets = [
        '{}', // Missing keys array
        '{"keys": []}', // Empty keys array
        '{"keys": [{}]}', // Single key (need 2)
        '{"keys": [{}, {}, {}]}', // Too many keys
      ];
      
      for (final String invalidJwkSet in invalidJwkSets) {
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

    test('property test - Import-export round trip', () async {
      final KeyDuoSerializer serializer = KeyDuoSerializer();
      
      for (int i = 0; i < expensiveIterations; i++) {
        final KeyDuo originalKeyDuo = await GenerationService.generateKeyDuo();
        
        final String jwkSetJson = await serializer.exportKeyDuo(originalKeyDuo);
        final KeyDuo importedKeyDuo = await serializer.importKeyDuo(jwkSetJson);
        final String reExportedJson = await serializer.exportKeyDuo(importedKeyDuo);
        
        final Map<String, dynamic> originalData = jsonDecode(jwkSetJson) as Map<String, dynamic>;
        final Map<String, dynamic> reExportedData = jsonDecode(reExportedJson) as Map<String, dynamic>;
        
        final List<dynamic> originalKeys = originalData['keys'] as List<dynamic>;
        final List<dynamic> reExportedKeys = reExportedData['keys'] as List<dynamic>;
        
        expect(originalKeys.length, equals(reExportedKeys.length),
               reason: 'Round-trip should preserve number of keys');
        
        // Verify both key sets contain the same key identifiers
        final Set<String> originalKids = originalKeys.map((k) => (k as Map<String, dynamic>)['kid'] as String).toSet();
        final Set<String> reExportedKids = reExportedKeys.map((k) => (k as Map<String, dynamic>)['kid'] as String).toSet();
        
        expect(originalKids, equals(reExportedKids),
               reason: 'Round-trip should preserve key identifiers');
        
        // Imported keys should be functional
        final ExportedJwk signingExport = await importedKeyDuo.signing.exportPrivateKey();
        final ExportedJwk encryptionExport = await importedKeyDuo.encryption.exportPrivateKey();
        
        expect(signingExport.alg, equals('ES256'),
               reason: 'Imported signing key should have correct algorithm');
        expect(encryptionExport.alg, equals('ECDH-ES+A256KW'),
               reason: 'Imported encryption key should have correct algorithm');
      }
    });

    test('property test - Public key export and import', () async {
      final KeyDuoSerializer serializer = KeyDuoSerializer();
      
      for (int i = 0; i < expensiveIterations; i++) {
        final KeyDuo originalKeyDuo = await GenerationService.generateKeyDuo();
        
        // Export public keys only
        final String publicJwkSetJson = await serializer.exportPublicKeyDuo(originalKeyDuo);
        final Map<String, dynamic> publicJwkSetData = jsonDecode(publicJwkSetJson) as Map<String, dynamic>;
        final List<dynamic> publicKeys = publicJwkSetData['keys'] as List<dynamic>;
        
        // Verify no private components
        for (final dynamic key in publicKeys) {
          final Map<String, dynamic> keyMap = key as Map<String, dynamic>;
          expect(keyMap.containsKey('d'), isFalse,
                 reason: 'Public key export must not contain private component d');
        }
        
        // Import public keys
        final IKeyDuo importedPublicKeyDuo = await serializer.importPublicKeyDuo(publicJwkSetJson);
        
        expect(importedPublicKeyDuo.signing.hasPrivateKey, isFalse,
               reason: 'Imported public signing key should not have private key');
        expect(importedPublicKeyDuo.encryption.hasPrivateKey, isFalse,
               reason: 'Imported public encryption key should not have private key');
      }
    });
  });

}

// ═══════════════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════════════

/// Generates a random EC JWK for thumbprint testing
Map<String, dynamic> _generateRandomEcJwk(Random random) {
  final String x = _generateRandomBase64Url(random, 32);
  final String y = _generateRandomBase64Url(random, 32);
  
  return {
    'kty': 'EC',
    'crv': 'P-256',
    'x': x,
    'y': y,
  };
}

/// Generates a random base64url string of specified byte length
String _generateRandomBase64Url(Random random, int byteLength) {
  final List<int> bytes = List<int>.generate(byteLength, (_) => random.nextInt(256));
  final String base64 = base64Encode(bytes);
  return base64.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

/// Generates a valid EC JWK with P-256 curve
Map<String, dynamic> _generateValidEcJwkData(Random random, {bool includePrivate = false}) {
  final String x = _generateRandomBase64Url(random, 32);
  final String y = _generateRandomBase64Url(random, 32);
  
  final Map<String, dynamic> jwk = <String, dynamic>{
    'kty': JwkKeyType.ec,
    'crv': JwkCurve.p256,
    'x': x,
    'y': y,
  };
  
  if (includePrivate) {
    jwk['d'] = _generateRandomBase64Url(random, 32);
  }
  
  return jwk;
}