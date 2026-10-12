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

// Property-based test iteration counts
const int lightweightIterations = 3; // For fast operations (hashing, object creation)
const int expensiveIterations = 1;   // For slow operations (key generation) - keep minimal

/// Members a 3.0 private/public JWK may carry. No `key_ops`, no `ext`.
const Set<String> _privateMembers = <String>{'kty', 'crv', 'x', 'y', 'd', 'kid', 'alg', 'use'};
const Set<String> _publicMembers = <String>{'kty', 'crv', 'x', 'y', 'kid', 'alg', 'use'};

void main() {
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
      await expectLater(
        calculateJwkThumbprint(<String, dynamic>{'kty': 'EC', 'crv': 'P-256', 'x': 'test'}),
        throwsA(isA<ArgumentError>()),
        reason: 'Should throw when missing required field "y"',
      );
    });
  });

  group('ExportedJwk DTO (obtained from key pair exports)', () {
    late KeyDuo keyDuo;
    setUp(() async => keyDuo = await GenerationService.generateKeyDuo());
    tearDown(() => keyDuo.dispose());

    test('signing key DTO carries kid, ES256 and sig', () async {
      final ExportedJwk export = await keyDuo.signing.exportPrivateKey();
      expect(export.keyId, equals(await keyDuo.signing.calculateKeyId()));
      expect(export.alg, equals(JwkAlgorithm.es256));
      expect(export.use, equals(JwkUse.signature));

      final Map<String, dynamic> json = export.toJson();
      expect(json['kid'], equals(export.keyId));
      expect(json['alg'], equals(JwkAlgorithm.es256));
      expect(json['use'], equals(JwkUse.signature));
      expect(json['kty'], equals(JwkKeyType.ec));
      expect(json.keys.toSet(), equals(_privateMembers),
          reason: 'exactly kty, crv, x, y, d, kid, alg, use');
    });

    test('encryption key DTO carries kid, HPKE-7 and enc', () async {
      final ExportedJwk export = await keyDuo.encryption.exportPrivateKey();
      expect(export.keyId, equals(await keyDuo.encryption.calculateKeyId()));
      expect(export.alg, equals('HPKE-7'));
      expect(export.alg, equals(JwkAlgorithm.hpke7));
      expect(export.use, equals(JwkUse.encryption));

      final Map<String, dynamic> json = export.toJson();
      expect(json['alg'], equals('HPKE-7'));
      expect(json['use'], equals('enc'));
      expect(json.keys.toSet(), equals(_privateMembers));
      expect(json.containsKey('key_ops'), isFalse);
      expect(json.containsKey('ext'), isFalse);
    });

    test('toPublicOnly strips d and keeps the public members', () async {
      final ExportedJwk privateExport = await keyDuo.signing.exportPrivateKey();
      final Map<String, dynamic> privateJson = privateExport.toJson();

      final ExportedJwk publicExport = privateExport.toPublicOnly();
      final Map<String, dynamic> publicJson = publicExport.toJson();

      expect(publicJson.keys.toSet(), equals(_publicMembers));
      expect(publicJson.containsKey('d'), isFalse);
      for (final String m in <String>['kty', 'crv', 'x', 'y', 'kid', 'alg', 'use']) {
        expect(publicJson[m], equals(privateJson[m]), reason: 'member $m preserved');
      }
    });

    test('exportPublicKey equals the private export without d', () async {
      for (final IKeyPair pair in <IKeyPair>[keyDuo.signing, keyDuo.encryption]) {
        final Map<String, dynamic> expected =
            (await pair.exportPrivateKey()).toJson()..remove('d');
        final Map<String, dynamic> actual = (await pair.exportPublicKey()).toJson();
        expect(actual, equals(expected));
      }
    });
  });

  group('SigningKeyPair (ECDSA P-256)', () {
    test('export includes correct metadata', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final SigningKeyPair signingKeyPair = keyDuo.signingKeyPair;

      final ExportedJwk privateExport = await signingKeyPair.exportPrivateKey();
      expect(privateExport.alg, equals(JwkAlgorithm.es256));
      expect(privateExport.use, equals(JwkUse.signature));
      expect(privateExport.keyId, matches(RegExp(r'^[A-Za-z0-9_-]+$')),
             reason: 'Key ID should be valid base64url format');

      final String keyId1 = await signingKeyPair.calculateKeyId();
      final String keyId2 = await signingKeyPair.calculateKeyId();
      expect(keyId1, equals(keyId2));
      expect(privateExport.keyId, equals(keyId1));

      final ExportedJwk publicExport = await signingKeyPair.exportPublicKey();
      expect(publicExport.alg, equals(JwkAlgorithm.es256));
      expect(publicExport.use, equals(JwkUse.signature));
      expect(publicExport.keyId, equals(privateExport.keyId));

      final Map<String, dynamic> privateJson = privateExport.toJson();
      expect(privateJson['crv'], equals(JwkCurve.p256));
      expect(privateJson.containsKey('d'), isTrue);
      final Map<String, dynamic> publicJson = publicExport.toJson();
      expect(publicJson.containsKey('d'), isFalse,
             reason: 'Public key export must not contain private component');
      keyDuo.dispose();
    });

    test('key pair validation, and public-only throws StateError', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      expect(await VerificationService.verifySigningKeyPair(keyDuo.signingKeyPair), isTrue);

      final SigningKeyPair publicOnly = await SigningKeyPair.importPublicKeyRaw(
          await keyDuo.signingKeyPair.exportPublicKeyRaw());
      expect(publicOnly.hasPrivateKey, isFalse);
      await expectLater(
        VerificationService.verifySigningKeyPair(publicOnly),
        throwsA(isA<StateError>()),
        reason: 'Public-only key pair should throw StateError on validation',
      );
      publicOnly.dispose();
      keyDuo.dispose();
    });

    test('sign and verify operations', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final SigningKeyPair signingKeyPair = keyDuo.signingKeyPair;

      final Uint8List message = Uint8List.fromList('test message'.codeUnits);
      final Uint8List signature = await signingKeyPair.signBytes(message);
      expect(signature.length, equals(64), reason: 'P1363 r||s is 64 bytes');
      expect(await signingKeyPair.verifyBytes(signature, message), isTrue);

      final Uint8List wrongMessage = Uint8List.fromList('wrong message'.codeUnits);
      expect(await signingKeyPair.verifyBytes(signature, wrongMessage), isFalse);

      // A malformed signature is false, never an error.
      expect(await signingKeyPair.verifyBytes(Uint8List(10), message), isFalse);
      keyDuo.dispose();
    });

    test('a public-only key pair verifies but cannot sign', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final Uint8List message = Uint8List.fromList('m'.codeUnits);
      final Uint8List signature = await keyDuo.signingKeyPair.signBytes(message);

      final SigningKeyPair publicOnly = await SigningKeyPair.importPublicKeyRaw(
          await keyDuo.signingKeyPair.exportPublicKeyRaw());
      expect(await publicOnly.verifyBytes(signature, message), isTrue);
      await expectLater(publicOnly.signBytes(message), throwsA(isA<StateError>()));
      publicOnly.dispose();
      keyDuo.dispose();
    });

    test('export public key as hex', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final SigningKeyPair signingKeyPair = keyDuo.signingKeyPair;

      final String publicKeySec1Hex = await signingKeyPair.exportPublicKeySec1Hex();
      expect(publicKeySec1Hex.length, equals(130));
      expect(publicKeySec1Hex, matches(RegExp(r'^04[0-9a-f]+$')));

      final Uint8List publicKeyRaw = await signingKeyPair.exportPublicKeyRaw();
      expect(publicKeyRaw.length, equals(65));
      expect(publicKeyRaw[0], equals(0x04));
      keyDuo.dispose();
    });
  });

  group('EncryptionKeyPair (HPKE P-256)', () {
    test('export includes correct metadata', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final EncryptionKeyPair encryptionKeyPair = keyDuo.encryptionKeyPair;

      final ExportedJwk privateExport = await encryptionKeyPair.exportPrivateKey();
      expect(privateExport.alg, equals('HPKE-7'));
      expect(privateExport.use, equals(JwkUse.encryption));
      expect(privateExport.keyId, isNotEmpty);

      expect(await encryptionKeyPair.calculateKeyId(), equals(privateExport.keyId));

      final ExportedJwk publicExport = await encryptionKeyPair.exportPublicKey();
      expect(publicExport.alg, equals('HPKE-7'));
      expect(publicExport.use, equals(JwkUse.encryption));
      expect(publicExport.keyId, equals(privateExport.keyId));

      expect(privateExport.toJson().containsKey('d'), isTrue);
      expect(publicExport.toJson().containsKey('d'), isFalse);
      keyDuo.dispose();
    });

    test('key pair validation, and public-only throws StateError', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      expect(await VerificationService.verifyEncryptionKeyPair(keyDuo.encryptionKeyPair), isTrue);

      final EncryptionKeyPair publicOnly = await EncryptionKeyPair.importPublicKeyRaw(
          await keyDuo.encryptionKeyPair.exportPublicKeyRaw());
      expect(publicOnly.hasPrivateKey, isFalse);
      await expectLater(
        VerificationService.verifyEncryptionKeyPair(publicOnly),
        throwsA(isA<StateError>()),
        reason: 'Public-only key pair should throw StateError on validation',
      );
      publicOnly.dispose();
      keyDuo.dispose();
    });
  });

  group('KeyDuo and GenerationService', () {
    test('generation produces correct key metadata and distinct keys', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();

      expect(keyDuo.signing.hasPrivateKey, isTrue);
      expect(keyDuo.encryption.hasPrivateKey, isTrue);

      final ExportedJwk signingExport = await keyDuo.signing.exportPrivateKey();
      expect(signingExport.alg, equals(JwkAlgorithm.es256));
      expect(signingExport.use, equals(JwkUse.signature));

      final ExportedJwk encryptionExport = await keyDuo.encryption.exportPrivateKey();
      expect(encryptionExport.alg, equals('HPKE-7'));
      expect(encryptionExport.use, equals(JwkUse.encryption));

      expect(signingExport.keyId, isNot(equals(encryptionExport.keyId)),
             reason: 'Signing and encryption keys must have different key IDs');
      expect(await keyDuo.signing.exportPublicKeySec1Hex(),
          isNot(equals(await keyDuo.encryption.exportPublicKeySec1Hex())));
      keyDuo.dispose();
    });

    test('generation uses P-256 EC keys with all components', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      for (final IKeyPair pair in <IKeyPair>[keyDuo.signing, keyDuo.encryption]) {
        final Map<String, dynamic> json = (await pair.exportPrivateKey()).toJson();
        expect(json['kty'], equals(JwkKeyType.ec));
        expect(json['crv'], equals(JwkCurve.p256));
        for (final String m in <String>['x', 'y', 'd']) {
          expect(json.containsKey(m), isTrue, reason: 'EC private key must contain $m');
          expect(base64Url.decode(base64Url.normalize(json[m] as String)).length, equals(32),
              reason: '$m is exactly 32 bytes');
        }
      }
      keyDuo.dispose();
    });

    test('exports are consistent between private and public', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      for (final IKeyPair pair in <IKeyPair>[keyDuo.signing, keyDuo.encryption]) {
        expect((await pair.exportPrivateKey()).keyId, equals((await pair.exportPublicKey()).keyId));
      }
      expect(identical(keyDuo.signing, keyDuo.encryption), isFalse);
      keyDuo.dispose();
    });

    test('signingKeyPair accessor signs and exports hex', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final SigningKeyPair signingKeyPair = keyDuo.signingKeyPair;

      final Uint8List signature = await signingKeyPair.signBytes(Uint8List.fromList('test'.codeUnits));
      expect(signature.length, equals(64));
      expect((await signingKeyPair.exportPublicKeySec1Hex()).length, equals(130));
      keyDuo.dispose();
    });
  });

  group('KeyDuoSerializer', () {
    const KeyDuoSerializer serializer = KeyDuoSerializer();

    test('JWK Set export structure', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final Map<String, dynamic> jwkSetData =
          jsonDecode(await serializer.exportKeyDuoJwk(keyDuo)) as Map<String, dynamic>;

      expect(jwkSetData.keys.toSet(), equals(<String>{'keys'}));
      final List<dynamic> keys = jwkSetData['keys'] as List<dynamic>;
      expect(keys.length, equals(2));

      for (final dynamic key in keys) {
        final Map<String, dynamic> keyMap = key as Map<String, dynamic>;
        expect(keyMap.keys.toSet(), equals(_privateMembers),
            reason: 'no key_ops, no ext');
      }

      final Set<String> uses = keys.map((dynamic k) => (k as Map<String, dynamic>)['use'] as String).toSet();
      expect(uses, equals(<String>{'sig', 'enc'}));
      keyDuo.dispose();
    });

    test('private key export completeness and algorithms', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final Map<String, dynamic> jwkSetData =
          jsonDecode(await serializer.exportKeyDuoJwk(keyDuo)) as Map<String, dynamic>;

      for (final dynamic key in jwkSetData['keys'] as List<dynamic>) {
        final Map<String, dynamic> keyMap = key as Map<String, dynamic>;
        expect(keyMap['kty'], equals('EC'));
        expect(keyMap['crv'], equals('P-256'));
        expect(keyMap.containsKey('d'), isTrue);
        expect(keyMap['alg'], equals(keyMap['use'] == 'sig' ? 'ES256' : 'HPKE-7'));
      }
      keyDuo.dispose();
    });

    test('JWK Set import returns usable functional keys', () async {
      final KeyDuo original = await GenerationService.generateKeyDuo();
      final KeyDuo imported =
          await serializer.importKeyDuoJwk(await serializer.exportKeyDuoJwk(original));

      expect(imported.signing.hasPrivateKey, isTrue);
      expect(imported.encryption.hasPrivateKey, isTrue);
      expect(await VerificationService.verifyKeyDuo(imported), isTrue);
      expect(await imported.exportPublicKeyDuo(), equals(await original.exportPublicKeyDuo()));
      original.dispose();
      imported.dispose();
    });

    test('import validation errors', () async {
      final List<String> invalidJwkSets = <String>[
        '{}', // Missing keys array
        '{"keys": []}', // Empty keys array
        '{"keys": [{}]}', // Single key (need 2)
        '{"keys": [{}, {}, {}]}', // Too many keys
        'invalid json',
      ];

      for (final String invalidJwkSet in invalidJwkSets) {
        await expectLater(
          serializer.importKeyDuoJwk(invalidJwkSet),
          throwsA(isA<FormatException>()),
          reason: 'Invalid JWK Set should throw FormatException: $invalidJwkSet',
        );
      }
    });

    test('a 2.x JWK Set (alg ECDH-ES+A256KW) is rejected', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final Map<String, dynamic> set =
          jsonDecode(await serializer.exportKeyDuoJwk(keyDuo)) as Map<String, dynamic>;
      for (final dynamic k in set['keys'] as List<dynamic>) {
        final Map<String, dynamic> m = k as Map<String, dynamic>;
        if (m['use'] == 'enc') m['alg'] = 'ECDH-ES+A256KW';
      }
      await expectLater(
        serializer.importKeyDuoJwk(jsonEncode(set)),
        throwsA(isA<FormatException>()),
      );
      keyDuo.dispose();
    });

    test('import-export round trip preserves key identifiers', () async {
      final KeyDuo original = await GenerationService.generateKeyDuo();
      final String jwkSetJson = await serializer.exportKeyDuoJwk(original);
      final KeyDuo imported = await serializer.importKeyDuoJwk(jwkSetJson);
      final String reExportedJson = await serializer.exportKeyDuoJwk(imported);

      final List<dynamic> originalKeys =
          (jsonDecode(jwkSetJson) as Map<String, dynamic>)['keys'] as List<dynamic>;
      final List<dynamic> reExportedKeys =
          (jsonDecode(reExportedJson) as Map<String, dynamic>)['keys'] as List<dynamic>;
      expect(reExportedKeys.length, equals(originalKeys.length));

      Set<String> kids(List<dynamic> ks) =>
          ks.map((dynamic k) => (k as Map<String, dynamic>)['kid'] as String).toSet();
      expect(kids(reExportedKeys), equals(kids(originalKeys)));

      expect((await imported.signing.exportPrivateKey()).alg, equals('ES256'));
      expect((await imported.encryption.exportPrivateKey()).alg, equals('HPKE-7'));
      original.dispose();
      imported.dispose();
    });

    test('public key export and import', () async {
      final KeyDuo original = await GenerationService.generateKeyDuo();
      final String publicJwkSetJson = await serializer.exportPublicKeyDuoJwk(original);
      final List<dynamic> publicKeys =
          (jsonDecode(publicJwkSetJson) as Map<String, dynamic>)['keys'] as List<dynamic>;

      for (final dynamic key in publicKeys) {
        expect((key as Map<String, dynamic>).keys.toSet(), equals(_publicMembers),
            reason: 'public export carries no d, key_ops or ext');
      }

      final IKeyDuo importedPublic = await serializer.importPublicKeyDuoJwk(publicJwkSetJson);
      expect(importedPublic.signing.hasPrivateKey, isFalse);
      expect(importedPublic.encryption.hasPrivateKey, isFalse);
      original.dispose();
      (importedPublic as KeyDuo).dispose();
    });
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════════════

/// Generates a random EC JWK for thumbprint testing
Map<String, dynamic> _generateRandomEcJwk(Random random) {
  return <String, dynamic>{
    'kty': 'EC',
    'crv': 'P-256',
    'x': _generateRandomBase64Url(random, 32),
    'y': _generateRandomBase64Url(random, 32),
  };
}

/// Generates a random base64url string of specified byte length
String _generateRandomBase64Url(Random random, int byteLength) {
  final List<int> bytes = List<int>.generate(byteLength, (_) => random.nextInt(256));
  return base64Encode(bytes).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
