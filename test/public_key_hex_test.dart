/// Tests for the typed public key hex wrappers.
///
/// A P-256 public key carries no indication of its purpose, so the only
/// defence against storing a signing key in an encryption key's field is the
/// type system. [SigningPublicKeyHex] and [EncryptionPublicKeyHex] are
/// zero-cost extension types that make that mistake a compile error.
///
/// The distinctness itself cannot be asserted at runtime — extension types
/// erase to `String`, which is the point: they cost nothing. What is asserted
/// here is that the wrappers validate, normalise, and thread through the API
/// correctly. The compile-time guarantee is demonstrated by the commented
/// counter-examples, which are deliberately not valid Dart.
library;

import 'package:test/test.dart';
import 'package:dart_jwk_duo/src/encryption_key_pair.dart';
import 'package:dart_jwk_duo/src/generation_service.dart';
import 'package:dart_jwk_duo/src/key_duo.dart';
import 'package:dart_jwk_duo/src/public_key_hex.dart';
import 'package:dart_jwk_duo/src/signing_key_pair.dart';

void main() {
  group('SigningPublicKeyHex', () {
    test('wraps a valid SEC1 hex string', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final String raw = await keyDuo.signingKeyPair.exportPublicKeySec1Hex();

      final SigningPublicKeyHex typed = SigningPublicKeyHex(raw);
      expect(typed.value, equals(raw));
      expect(typed.length, equals(130),
          reason: 'It implements String, so String members still work');
    });

    test('rejects anything that is not a SEC1 P-256 point', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final String valid = await keyDuo.signingKeyPair.exportPublicKeySec1Hex();

      expect(() => SigningPublicKeyHex(''), throwsA(isA<FormatException>()));
      expect(() => SigningPublicKeyHex(valid.substring(2)),
          throwsA(isA<FormatException>()),
          reason: 'The bare 128-hex form is not a SEC1 point');
      expect(() => SigningPublicKeyHex('02${valid.substring(2)}'),
          throwsA(isA<FormatException>()),
          reason: 'A compressed tag is not accepted');
      expect(() => SigningPublicKeyHex('${valid.substring(0, 128)}zz'),
          throwsA(isA<FormatException>()),
          reason: 'Non-hex characters are rejected');
    });

    test('normalises to lowercase so equality is reliable', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final String raw = await keyDuo.signingKeyPair.exportPublicKeySec1Hex();

      expect(SigningPublicKeyHex(raw.toUpperCase()).value, equals(raw),
          reason:
              'Two spellings of the same key must not compare as different keys');
      expect(SigningPublicKeyHex(raw.toUpperCase()),
          equals(SigningPublicKeyHex(raw)));
    });
  });

  group('EncryptionPublicKeyHex', () {
    test('wraps and validates identically to the signing wrapper', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final String raw =
          await keyDuo.encryptionKeyPair.exportPublicKeySec1Hex();

      expect(EncryptionPublicKeyHex(raw).value, equals(raw));
      expect(() => EncryptionPublicKeyHex(raw.substring(2)),
          throwsA(isA<FormatException>()),
          reason: 'Both wrappers enforce exactly the same encoding');
    });
  });

  group('Typed accessors on the key pairs', () {
    test('each pair type narrows the return type to its own hex type',
        () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();

      // Same method name as on IKeyPair — the concrete types narrow the
      // return type covariantly, so there is only ever one name to remember.
      final SigningPublicKeyHex signing =
          await keyDuo.signingKeyPair.exportPublicKeySec1Hex();
      final EncryptionPublicKeyHex encryption =
          await keyDuo.encryptionKeyPair.exportPublicKeySec1Hex();

      expect(signing.value.length, equals(130));
      expect(encryption.value.length, equals(130));
      expect(signing.value, isNot(equals(encryption.value)));

      // The following do not compile, which is the entire point:
      //
      //   final EncryptionPublicKeyHex wrong =
      //       await keyDuo.signingKeyPair.exportPublicKeySec1Hex();
      //
      //   await SigningKeyPair.importPublicKeySec1Hex(encryption);
      //
      // Both were plain Strings before, and would have been accepted.
    });

    test('the interface still yields a plain String', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();

      // Through IKeyPair the purpose is not known, so the type is not either.
      final String viaInterface =
          await keyDuo.signing.exportPublicKeySec1Hex();
      expect(viaInterface.length, equals(130));
    });

    test('typed hex round trips back through import', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();

      final SigningPublicKeyHex signing =
          await keyDuo.signingKeyPair.exportPublicKeySec1Hex();
      final EncryptionPublicKeyHex encryption =
          await keyDuo.encryptionKeyPair.exportPublicKeySec1Hex();

      final SigningKeyPair importedSigning =
          await SigningKeyPair.importPublicKeySec1Hex(signing);
      final EncryptionKeyPair importedEncryption =
          await EncryptionKeyPair.importPublicKeySec1Hex(encryption);

      expect(await importedSigning.exportPublicKeySec1Hex(), equals(signing));
      expect(
          await importedEncryption.exportPublicKeySec1Hex(), equals(encryption));
    });

    test('a raw string from storage must be wrapped explicitly', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      // Simulates a value read back out of a database column.
      final String fromStorage =
          (await keyDuo.signingKeyPair.exportPublicKeySec1Hex()).value;

      // The wrap is the one place where a bare String becomes a key of a
      // stated purpose: explicit, greppable, and validating.
      final SigningKeyPair imported = await SigningKeyPair.importPublicKeySec1Hex(
          SigningPublicKeyHex(fromStorage));
      expect((await imported.exportPublicKeySec1Hex()).value,
          equals(fromStorage));
    });
  });

  group('PublicKeyDuo', () {
    test('carries both keys in labelled slots', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final PublicKeyDuo duo = await keyDuo.exportPublicKeyDuo();

      expect(duo.signing.value,
          equals(await keyDuo.signingKeyPair.exportPublicKeySec1Hex()));
      expect(duo.encryption.value,
          equals(await keyDuo.encryptionKeyPair.exportPublicKeySec1Hex()));

      // Constructing one with the arguments swapped does not compile —
      // the slots have different types, so the classic transposition bug
      // cannot be written.
    });

    test('rejects a duo whose two keys are the same', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final String signing =
          await keyDuo.signingKeyPair.exportPublicKeySec1Hex();

      expect(
          () => PublicKeyDuo(
                signing: SigningPublicKeyHex(signing),
                encryption: EncryptionPublicKeyHex(signing),
              ),
          throwsA(isA<ArgumentError>()),
          reason:
              'The same key in both slots means one was copied into the other '
              'field — the exact bug these types exist to prevent');
    });

    test('round trips through JSON', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final PublicKeyDuo duo = await keyDuo.exportPublicKeyDuo();

      final PublicKeyDuo restored = PublicKeyDuo.fromJson(duo.toJson());
      expect(restored, equals(duo),
          reason: 'A wire round trip must preserve both keys and their slots');
      expect(restored.signing.value, equals(duo.signing.value));
      expect(restored.encryption.value, equals(duo.encryption.value));
    });

    test('JSON field names state the purpose explicitly', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final Map<String, dynamic> json =
          (await keyDuo.exportPublicKeyDuo()).toJson();

      expect(json.keys.toSet(),
          equals(<String>{'signingPublicKeyHex', 'encryptionPublicKeyHex'}),
          reason:
              'Field names carry purpose across the wire, where types cannot');
    });

    test('fromJson rejects a malformed or incomplete payload', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final Map<String, dynamic> json =
          (await keyDuo.exportPublicKeyDuo()).toJson();

      expect(
          () => PublicKeyDuo.fromJson(<String, dynamic>{
                'signingPublicKeyHex': json['signingPublicKeyHex'],
              }),
          throwsA(isA<FormatException>()),
          reason: 'A missing key must fail loudly, not default to null');

      expect(
          () => PublicKeyDuo.fromJson(<String, dynamic>{
                'signingPublicKeyHex': 'nonsense',
                'encryptionPublicKeyHex': json['encryptionPublicKeyHex'],
              }),
          throwsA(isA<FormatException>()),
          reason: 'Values are validated on the way in, not trusted');
    });
  });
}
