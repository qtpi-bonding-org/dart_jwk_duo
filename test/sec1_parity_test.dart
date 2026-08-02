/// Tests for the SEC1 uncompressed public key surface.
///
/// This library speaks exactly one public key encoding: SEC1 uncompressed
/// (`04 || x || y`), 65 bytes / 130 hex characters. These tests pin that
/// contract and pin the symmetry between [SigningKeyPair] and
/// [EncryptionKeyPair] — the two types must be interchangeable at the
/// encoding boundary so that callers never have to pick an encoding based
/// on which key type they happen to hold.
library;

import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dart_jwk_duo/src/constants.dart';
import 'package:dart_jwk_duo/src/hex_codec.dart';
import 'package:dart_jwk_duo/src/interfaces.dart';
import 'package:dart_jwk_duo/src/key_duo.dart';
import 'package:dart_jwk_duo/src/key_duo_serializer.dart';
import 'package:dart_jwk_duo/src/public_key_hex.dart';
import 'package:dart_jwk_duo/src/generation_service.dart';
import 'package:dart_jwk_duo/src/signing_key_pair.dart';
import 'package:dart_jwk_duo/src/encryption_key_pair.dart';
import 'package:dart_jwk_duo/src/crypto_service.dart';
import 'package:dart_jwk_duo/src/verification_service.dart';

/// Number of independently generated key duos used by property-style tests.
const int keyDuoIterations = 3;

void main() {
  group('SEC1 constants', () {
    test('sizes are internally consistent', () {
      expect(CryptoSizes.ecP256Sec1PublicKeyLength, equals(65),
          reason: 'SEC1 uncompressed P-256 point is 1 tag + 32 x + 32 y bytes');
      expect(CryptoSizes.ecP256Sec1PublicKeyHexLength,
          equals(CryptoSizes.ecP256Sec1PublicKeyLength * 2),
          reason: 'Hex length must be exactly twice the byte length');
      expect(CryptoSizes.sec1UncompressedTag, equals(0x04),
          reason: 'SEC1 uncompressed point tag is 0x04');
    });
  });

  group('HexCodec', () {
    test('encode produces lowercase, zero-padded hex', () {
      final Uint8List bytes = Uint8List.fromList(<int>[0x00, 0x0f, 0xa5, 0xff]);
      expect(HexCodec.encode(bytes), equals('000fa5ff'),
          reason: 'Each byte must render as exactly two lowercase hex digits');
    });

    test('encode and decode round trip', () {
      final Uint8List bytes =
          Uint8List.fromList(List<int>.generate(64, (int i) => i * 3 % 256));
      final String hex = HexCodec.encode(bytes);
      expect(hex.length, equals(128));
      expect(HexCodec.decode(hex, expectedLength: 128), equals(bytes),
          reason: 'decode(encode(x)) must be x');
    });

    test('decode accepts uppercase hex', () {
      expect(HexCodec.decode('ABCDEF', expectedLength: 6),
          equals(Uint8List.fromList(<int>[0xab, 0xcd, 0xef])),
          reason: 'Uppercase input is valid hex even though we never emit it');
    });

    test('decode rejects wrong length and non-hex characters', () {
      expect(() => HexCodec.decode('abcd', expectedLength: 6),
          throwsA(isA<FormatException>()),
          reason: 'Length mismatch must be rejected');
      expect(() => HexCodec.decode('abcz', expectedLength: 4),
          throwsA(isA<FormatException>()),
          reason: 'Non-hex characters must be rejected');
      expect(() => HexCodec.decode('ab cd', expectedLength: 5),
          throwsA(isA<FormatException>()),
          reason: 'Whitespace must be rejected, not silently stripped');
    });
  });

  group('SEC1 export — shape', () {
    test('both pair types export exactly 130 lowercase hex chars tagged 04',
        () async {
      for (int i = 0; i < keyDuoIterations; i++) {
        final KeyDuo keyDuo = await GenerationService.generateKeyDuo();

        for (final MapEntry<String, IKeyPair<Object?, Object?>> entry
            in <String, IKeyPair<Object?, Object?>>{
          'signing': keyDuo.signingKeyPair,
          'encryption': keyDuo.encryptionKeyPair,
        }.entries) {
          final String label = entry.key;
          final String hex = await entry.value.exportPublicKeySec1Hex();

          expect(hex.length, equals(CryptoSizes.ecP256Sec1PublicKeyHexLength),
              reason: '$label SEC1 hex must be exactly 130 characters');
          expect(hex.startsWith('04'), isTrue,
              reason: '$label SEC1 hex must begin with the 04 tag');
          expect(hex, matches(RegExp(r'^[0-9a-f]+$')),
              reason: '$label SEC1 hex must be lowercase hex only');

          final Uint8List raw = await entry.value.exportPublicKeyRaw();
          expect(raw.length, equals(CryptoSizes.ecP256Sec1PublicKeyLength),
              reason: '$label raw export must be 65 bytes');
          expect(raw[0], equals(CryptoSizes.sec1UncompressedTag),
              reason: '$label raw export must begin with 0x04');
          expect(HexCodec.encode(raw), equals(hex),
              reason: '$label hex export must be the hex of the raw export');
        }
      }
    });
  });

  group('SEC1 round trip', () {
    test('signing: export -> import -> export is byte-identical', () async {
      for (int i = 0; i < keyDuoIterations; i++) {
        final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
        final SigningPublicKeyHex original =
            await keyDuo.signingKeyPair.exportPublicKeySec1Hex();

        final SigningKeyPair imported =
            await SigningKeyPair.importPublicKeySec1Hex(original);
        expect(await imported.exportPublicKeySec1Hex(), equals(original),
            reason: 'Signing SEC1 hex round trip must be exact');
        expect(imported.hasPrivateKey, isFalse,
            reason: 'Importing a public key must not synthesise a private key');

        final SigningKeyPair fromRaw = await SigningKeyPair.importPublicKeyRaw(
            await keyDuo.signingKeyPair.exportPublicKeyRaw());
        expect(await fromRaw.exportPublicKeySec1Hex(), equals(original),
            reason: 'Signing raw round trip must agree with the hex round trip');
      }
    });

    test('encryption: export -> import -> export is byte-identical', () async {
      for (int i = 0; i < keyDuoIterations; i++) {
        final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
        final EncryptionPublicKeyHex original =
            await keyDuo.encryptionKeyPair.exportPublicKeySec1Hex();

        final EncryptionKeyPair imported =
            await EncryptionKeyPair.importPublicKeySec1Hex(original);
        expect(await imported.exportPublicKeySec1Hex(), equals(original),
            reason: 'Encryption SEC1 hex round trip must be exact');
        expect(imported.hasPrivateKey, isFalse,
            reason: 'Importing a public key must not synthesise a private key');

        final EncryptionKeyPair fromRaw =
            await EncryptionKeyPair.importPublicKeyRaw(
                await keyDuo.encryptionKeyPair.exportPublicKeyRaw());
        expect(await fromRaw.exportPublicKeySec1Hex(), equals(original),
            reason:
                'Encryption raw round trip must agree with the hex round trip');
      }
    });

    test('a round-tripped signing key still verifies its own signatures',
        () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final Uint8List message = Uint8List.fromList('round-trip'.codeUnits);
      final Uint8List signature = await keyDuo.signingKeyPair.signBytes(message);

      final SigningKeyPair imported = await SigningKeyPair.importPublicKeySec1Hex(
          await keyDuo.signingKeyPair.exportPublicKeySec1Hex());

      expect(await imported.verifyBytes(signature, message), isTrue,
          reason:
              'A key that survives the encoding boundary must still be the same key');
    });

    test('a round-tripped encryption key still receives encrypted data',
        () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final Uint8List message = Uint8List.fromList('secret payload'.codeUnits);

      final EncryptionKeyPair recipient =
          await EncryptionKeyPair.importPublicKeySec1Hex(
              await keyDuo.encryptionKeyPair.exportPublicKeySec1Hex());

      final Uint8List ciphertext =
          await CryptoService.encrypt(message, recipient);
      final Uint8List plaintext =
          await CryptoService.decrypt(ciphertext, keyDuo.encryptionKeyPair);

      expect(plaintext, equals(message),
          reason:
              'Encrypting to a SEC1-imported public key must decrypt with the original private key');
    });
  });

  group('SEC1 import — rejection', () {
    late SigningPublicKeyHex validSigningHex;
    late EncryptionPublicKeyHex validEncryptionHex;

    setUp(() async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      validSigningHex = await keyDuo.signingKeyPair.exportPublicKeySec1Hex();
      validEncryptionHex =
          await keyDuo.encryptionKeyPair.exportPublicKeySec1Hex();
    });

    // Encoding is checked synchronously, when a bare String is declared to be
    // a key of a given purpose. That is the earliest possible point.

    test('rejects the bare 128-hex coordinate form', () {
      // The tag-stripped form this library used to emit is no longer accepted.
      final String bare = validSigningHex.substring(2);
      expect(bare.length, equals(128));
      expect(() => SigningPublicKeyHex(bare), throwsA(isA<FormatException>()),
          reason: 'Bare coordinates are not SEC1 and must be rejected outright');
      expect(() => EncryptionPublicKeyHex(bare), throwsA(isA<FormatException>()),
          reason: 'Both pair types must reject the bare form identically');
    });

    test('rejects wrong length', () {
      for (final String bad in <String>[
        '',
        '04',
        validSigningHex.substring(0, 128),
        '${validSigningHex}00',
      ]) {
        expect(() => SigningPublicKeyHex(bad), throwsA(isA<FormatException>()),
            reason: 'Signing hex must reject length ${bad.length}');
        expect(() => EncryptionPublicKeyHex(bad),
            throwsA(isA<FormatException>()),
            reason: 'Encryption hex must reject length ${bad.length}');
      }
    });

    test('rejects non-hex characters', () {
      final String bad = '${validSigningHex.substring(0, 128)}zz';
      expect(bad.length, equals(130));
      expect(() => SigningPublicKeyHex(bad), throwsA(isA<FormatException>()),
          reason: 'Non-hex characters must be rejected, not coerced');
      expect(() => EncryptionPublicKeyHex(bad), throwsA(isA<FormatException>()),
          reason: 'Both pair types must reject non-hex identically');
    });

    test('rejects a 130-hex string whose tag byte is not 04', () {
      // 02/03 are the SEC1 *compressed* tags; 00 is the point at infinity.
      // None of them are valid here even though the length is right.
      for (final String tag in <String>['00', '02', '03', '05', 'ff']) {
        final String badSigning = '$tag${validSigningHex.substring(2)}';
        expect(badSigning.length, equals(130));
        expect(() => SigningPublicKeyHex(badSigning),
            throwsA(isA<FormatException>()),
            reason: 'Signing hex must reject tag byte 0x$tag');
        expect(
            () => EncryptionPublicKeyHex(
                '$tag${validEncryptionHex.substring(2)}'),
            throwsA(isA<FormatException>()),
            reason: 'Encryption hex must reject tag byte 0x$tag');
      }
    });

    test('a point not on the P-256 curve is well-encoded but unimportable',
        () async {
      // Flip the low bit of the final y byte. The result is still 04-tagged,
      // still 130 hex chars, and still parses as hex — but it is not a point
      // on the curve. This pins exactly where each check happens: the string
      // wrapper cannot know (it is synchronous), so the import must, and does.
      final Uint8List raw =
          HexCodec.decode(validSigningHex, expectedLength: 130);
      raw[raw.length - 1] ^= 0x01;
      final String offCurve = HexCodec.encode(raw);

      expect(offCurve.length, equals(130));
      expect(offCurve.startsWith('04'), isTrue);
      expect(offCurve, isNot(equals(validSigningHex)));

      // Encoding is fine, so the wrapper accepts it.
      final SigningPublicKeyHex wrapped = SigningPublicKeyHex(offCurve);

      // Curve membership is not, so the import refuses it.
      await expectLater(SigningKeyPair.importPublicKeySec1Hex(wrapped),
          throwsA(isA<FormatException>()),
          reason: 'An off-curve point must not import as a signing key');

      final Uint8List encRaw =
          HexCodec.decode(validEncryptionHex, expectedLength: 130);
      encRaw[encRaw.length - 1] ^= 0x01;
      await expectLater(
          EncryptionKeyPair.importPublicKeySec1Hex(
              EncryptionPublicKeyHex(HexCodec.encode(encRaw))),
          throwsA(isA<FormatException>()),
          reason: 'An off-curve point must not import as an encryption key');
    });

    test('importPublicKeyRaw rejects wrong byte length and wrong tag',
        () async {
      await expectLater(
          SigningKeyPair.importPublicKeyRaw(Uint8List(64)),
          throwsA(isA<FormatException>()),
          reason: 'A 64-byte input is the bare form and must be rejected');
      await expectLater(
          EncryptionKeyPair.importPublicKeyRaw(Uint8List(64)),
          throwsA(isA<FormatException>()),
          reason: 'Both pair types must reject the bare byte form');

      final Uint8List wrongTag =
          HexCodec.decode(validSigningHex, expectedLength: 130);
      wrongTag[0] = 0x02;
      await expectLater(SigningKeyPair.importPublicKeyRaw(wrongTag),
          throwsA(isA<FormatException>()),
          reason: 'Raw import must enforce the 0x04 tag too');
    });
  });

  group('Key distinctness', () {
    test('two independently generated key duos share no public key', () async {
      final Set<String> seen = <String>{};

      for (int i = 0; i < keyDuoIterations; i++) {
        final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
        final String signing =
            await keyDuo.signingKeyPair.exportPublicKeySec1Hex();
        final String encryption =
            await keyDuo.encryptionKeyPair.exportPublicKeySec1Hex();

        expect(seen.add(signing), isTrue,
            reason: 'A signing public key must never repeat across key duos');
        expect(seen.add(encryption), isTrue,
            reason:
                'An encryption public key must never repeat, or collide with a signing key');
      }
    });

    test('within one key duo the signing and encryption keys differ', () async {
      for (int i = 0; i < keyDuoIterations; i++) {
        final KeyDuo keyDuo = await GenerationService.generateKeyDuo();

        expect(await keyDuo.signingKeyPair.exportPublicKeySec1Hex(),
            isNot(equals(await keyDuo.encryptionKeyPair.exportPublicKeySec1Hex())),
            reason:
                'Downstream asserts this as an invariant; it must hold at the source');
        expect(await keyDuo.signingKeyPair.calculateKeyId(),
            isNot(equals(await keyDuo.encryptionKeyPair.calculateKeyId())),
            reason: 'Distinct keys must have distinct thumbprints');
      }
    });
  });

  group('Signing and encryption keys are byte-indistinguishable', () {
    test('nothing in the encoding reveals which purpose a key serves',
        () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();

      final SigningPublicKeyHex signing =
          await keyDuo.signingKeyPair.exportPublicKeySec1Hex();
      final EncryptionPublicKeyHex encryption =
          await keyDuo.encryptionKeyPair.exportPublicKeySec1Hex();

      expect(signing.length, equals(encryption.length),
          reason: 'Equal length: length carries no purpose information');
      expect(signing.substring(0, 2), equals(encryption.substring(0, 2)),
          reason: 'Equal tag byte: the prefix carries no purpose information');
      expect(RegExp(r'^[0-9a-f]+$').hasMatch(signing), isTrue);
      expect(RegExp(r'^[0-9a-f]+$').hasMatch(encryption), isTrue,
          reason: 'Same alphabet: the charset carries no purpose information');

      // The consequence: a signing key's bytes import happily as an
      // encryption key and vice versa. Purpose lives in field names and
      // types, never in the bytes — anyone trying to sniff key type later
      // should trip over this test.
      //
      // Note that deliberately re-labelling requires writing out the wrong
      // wrapper by hand. Accidentally doing so is a compile error; only this
      // explicit, conspicuous re-wrap makes it possible.
      final EncryptionKeyPair signingBytesAsEncryptionKey =
          await EncryptionKeyPair.importPublicKeySec1Hex(
              EncryptionPublicKeyHex(signing.value));
      expect(await signingBytesAsEncryptionKey.exportPublicKeySec1Hex(),
          equals(signing),
          reason:
              'A signing public key is a valid P-256 point, so it imports as an ECDH key');

      final SigningKeyPair encryptionBytesAsSigningKey =
          await SigningKeyPair.importPublicKeySec1Hex(
              SigningPublicKeyHex(encryption.value));
      expect(await encryptionBytesAsSigningKey.exportPublicKeySec1Hex(),
          equals(encryption),
          reason:
              'An encryption public key is a valid P-256 point, so it imports as an ECDSA key');
    });
  });

  group('API parity between the two pair types', () {
    test('the export surface is reachable through the IKeyPair interface',
        () async {
      // If either pair type ever loses a member, this stops compiling.
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final List<IKeyPair<Object?, Object?>> pairs =
          <IKeyPair<Object?, Object?>>[
        keyDuo.signingKeyPair,
        keyDuo.encryptionKeyPair,
      ];

      for (final IKeyPair<Object?, Object?> pair in pairs) {
        expect((await pair.exportPublicKeySec1Hex()).length, equals(130));
        expect((await pair.exportPublicKeyRaw()).length, equals(65));
        expect(await pair.calculateKeyId(), isNotEmpty);
        expect((await pair.exportPublicKey()).keyId, isNotEmpty);
      }
    });

    test('both pair types expose the same static import surface', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();

      final SigningPublicKeyHex signing =
          await keyDuo.signingKeyPair.exportPublicKeySec1Hex();
      final EncryptionPublicKeyHex encryption =
          await keyDuo.encryptionKeyPair.exportPublicKeySec1Hex();

      // Statics cannot live on an interface, so parity is asserted here.
      expect(await SigningKeyPair.importPublicKeySec1Hex(signing),
          isA<SigningKeyPair>());
      expect(
          await SigningKeyPair.importPublicKeyRaw(
              HexCodec.decode(signing.value, expectedLength: 130)),
          isA<SigningKeyPair>());
      expect(await EncryptionKeyPair.importPublicKeySec1Hex(encryption),
          isA<EncryptionKeyPair>());
      expect(
          await EncryptionKeyPair.importPublicKeyRaw(
              HexCodec.decode(encryption.value, expectedLength: 130)),
          isA<EncryptionKeyPair>());
    });

    test('the serializer extracts both public keys in the same encoding',
        () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      const KeyDuoSerializer serializer = KeyDuoSerializer();
      final String jwkSetJson = await serializer.exportKeyDuo(keyDuo);

      final String signing =
          await KeyDuoSerializer.extractSigningPublicKeySec1Hex(jwkSetJson);
      final String encryption =
          await KeyDuoSerializer.extractEncryptionPublicKeySec1Hex(jwkSetJson);

      expect(signing,
          equals(await keyDuo.signingKeyPair.exportPublicKeySec1Hex()),
          reason: 'Extraction from JWK must agree with direct export');
      expect(encryption,
          equals(await keyDuo.encryptionKeyPair.exportPublicKeySec1Hex()),
          reason: 'Extraction from JWK must agree with direct export');
      expect(signing.length, equals(encryption.length),
          reason: 'Both extractors must return the same encoding');
    });
  });

  group('Verification via SEC1 hex', () {
    test('accepts a genuine signature and rejects a tampered one', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final Uint8List message = Uint8List.fromList('verify me'.codeUnits);
      final Uint8List signature = await keyDuo.signingKeyPair.signBytes(message);
      final SigningPublicKeyHex publicKeySec1Hex =
          await keyDuo.signingKeyPair.exportPublicKeySec1Hex();

      expect(
          await VerificationService.verifySignatureWithPublicKeySec1Hex(
            publicKeySec1Hex: publicKeySec1Hex,
            signature: signature,
            data: message,
          ),
          isTrue,
          reason: 'A genuine signature must verify');

      final Uint8List tampered = Uint8List.fromList(message)..[0] ^= 0x01;
      expect(
          await VerificationService.verifySignatureWithPublicKeySec1Hex(
            publicKeySec1Hex: publicKeySec1Hex,
            signature: signature,
            data: tampered,
          ),
          isFalse,
          reason: 'A signature over different data must not verify');
    });

    test('rejects a malformed public key rather than returning false',
        () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final Uint8List message = Uint8List.fromList('verify me'.codeUnits);
      final Uint8List signature = await keyDuo.signingKeyPair.signBytes(message);

      expect(
          () => VerificationService.verifySignatureWithPublicKeySec1Hex(
                publicKeySec1Hex: SigningPublicKeyHex('not-a-key'),
                signature: signature,
                data: message,
              ),
          throwsA(isA<FormatException>()),
          reason:
              'A malformed key is a caller bug, not a failed verification — '
              'silently returning false would hide it');
    });
  });

  group('Encrypt-to-public-key parity', () {
    test('a public-only encryption key pair can receive data', () async {
      final KeyDuo recipientDuo = await GenerationService.generateKeyDuo();
      final Uint8List message =
          Uint8List.fromList('for your eyes only'.codeUnits);

      // The sender holds nothing but the recipient's public key hex —
      // mirroring how a public-only SigningKeyPair can verify signatures.
      final EncryptionKeyPair recipientPublicOnly =
          await EncryptionKeyPair.importPublicKeySec1Hex(
              await recipientDuo.encryptionKeyPair.exportPublicKeySec1Hex());
      expect(recipientPublicOnly.hasPrivateKey, isFalse);

      final Uint8List ciphertext =
          await CryptoService.encrypt(message, recipientPublicOnly);

      expect(
          await CryptoService.decrypt(
              ciphertext, recipientDuo.encryptionKeyPair),
          equals(message),
          reason: 'Only the holder of the private key can read the result');
    });

    test('decrypting with a public-only key pair fails cleanly', () async {
      final KeyDuo recipientDuo = await GenerationService.generateKeyDuo();
      final EncryptionKeyPair recipientPublicOnly =
          await EncryptionKeyPair.importPublicKeySec1Hex(
              await recipientDuo.encryptionKeyPair.exportPublicKeySec1Hex());

      final Uint8List ciphertext = await CryptoService.encrypt(
          Uint8List.fromList('data'.codeUnits), recipientPublicOnly);

      await expectLater(CryptoService.decrypt(ciphertext, recipientPublicOnly),
          throwsA(isA<StateError>()),
          reason: 'Decryption without a private key must be a StateError');
    });

    test('a different recipient cannot decrypt', () async {
      final KeyDuo intended = await GenerationService.generateKeyDuo();
      final KeyDuo eavesdropper = await GenerationService.generateKeyDuo();

      final Uint8List ciphertext = await CryptoService.encrypt(
          Uint8List.fromList('private'.codeUnits), intended.encryptionKeyPair);

      await expectLater(
          CryptoService.decrypt(ciphertext, eavesdropper.encryptionKeyPair),
          throwsA(anything),
          reason: 'AES-GCM authentication must fail for the wrong key');
    });

    test('signing operates on a signing key pair, symmetrically', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final Uint8List message = Uint8List.fromList('symmetry'.codeUnits);

      // sign/verify take a SigningKeyPair exactly as encrypt/decrypt take an
      // EncryptionKeyPair. Neither needs a whole KeyDuo.
      final Uint8List signature =
          await CryptoService.sign(message, keyDuo.signingKeyPair);
      expect(
          await CryptoService.verifySignature(
              message, signature, keyDuo.signingKeyPair),
          isTrue,
          reason: 'CryptoService must accept the specific pair type');

      final SigningKeyPair publicOnly =
          await SigningKeyPair.importPublicKeySec1Hex(
              await keyDuo.signingKeyPair.exportPublicKeySec1Hex());
      expect(
          await CryptoService.verifySignature(message, signature, publicOnly),
          isTrue,
          reason: 'Verifying with a public-only pair must work');
    });
  });
}
