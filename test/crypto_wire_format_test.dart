/// Tests for the hybrid encryption wire format.
///
/// The format is fixed-layout with no length prefixes and no embedded JSON:
///
/// ```
/// | ephemeral SEC1 public key | HKDF salt | AES-GCM IV | ciphertext + tag |
/// |         65 bytes          | 32 bytes  |  12 bytes  |     variable     |
/// ```
///
/// Every field is a constant size, so parsing is a set of fixed offsets and
/// there is nothing for an attacker to inflate. These tests pin that layout
/// and pin that tampering with any field is detected.
library;

import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dart_jwk_duo/src/constants.dart';
import 'package:dart_jwk_duo/src/crypto_service.dart';
import 'package:dart_jwk_duo/src/encryption_key_pair.dart';
import 'package:dart_jwk_duo/src/generation_service.dart';
import 'package:dart_jwk_duo/src/key_duo.dart';
import 'package:dart_jwk_duo/src/sec1_public_key.dart';
import 'package:dart_jwk_duo/src/symmetric_key.dart';

/// Byte offset of the HKDF salt within an encrypted blob.
const int saltOffset = CryptoSizes.ecP256Sec1PublicKeyLength;

/// Byte offset of the AES-GCM IV within an encrypted blob.
const int ivOffset = saltOffset + CryptoSizes.hkdfSaltLength;

/// Byte offset of the ciphertext within an encrypted blob.
const int ciphertextOffset = ivOffset + CryptoSizes.aesGcmIvLength;

void main() {
  group('Wire format layout', () {
    test('header sizes are fixed and add up', () {
      expect(CryptoSizes.hybridHeaderLength, equals(ciphertextOffset),
          reason: 'The declared header length must match the field layout');
      expect(CryptoSizes.hybridHeaderLength, equals(65 + 32 + 12));
      expect(CryptoSizes.aesGcmTagLength, equals(16),
          reason: 'AES-GCM produces a 128-bit authentication tag');
    });

    test('an encrypted blob is exactly header + plaintext + tag', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();

      for (final int plaintextLength in <int>[0, 1, 16, 17, 1000]) {
        final Uint8List plaintext = Uint8List(plaintextLength);
        final Uint8List blob =
            await CryptoService.encrypt(plaintext, keyDuo.encryptionKeyPair);

        expect(
            blob.length,
            equals(CryptoSizes.hybridHeaderLength +
                plaintextLength +
                CryptoSizes.aesGcmTagLength),
            reason:
                'Length must be fully determined by the plaintext length — '
                'no length prefixes, no variable-size encoding');
      }
    });

    test('the blob begins with a usable SEC1 ephemeral public key', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final Uint8List blob = await CryptoService.encrypt(
          Uint8List.fromList('payload'.codeUnits), keyDuo.encryptionKeyPair);

      final Uint8List ephemeral =
          Uint8List.sublistView(blob, 0, CryptoSizes.ecP256Sec1PublicKeyLength);

      expect(ephemeral[0], equals(CryptoSizes.sec1UncompressedTag),
          reason: 'The ephemeral key is a SEC1 uncompressed point');
      expect(() => Sec1PublicKey.validateRaw(ephemeral), returnsNormally);

      // It is a real key, not just well-shaped bytes.
      final EncryptionKeyPair parsed =
          await EncryptionKeyPair.importPublicKeyRaw(ephemeral);
      expect(await parsed.exportPublicKeyRaw(), equals(ephemeral),
          reason: 'The embedded ephemeral key must round trip like any other');
    });

    test('overhead is constant, so nothing variable-length is embedded',
        () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final Uint8List plaintext = Uint8List.fromList('payload'.codeUnits);

      // The old format embedded the ephemeral key as a JSON JWK, whose length
      // varied run to run with the base64url encoding of the coordinates.
      // A constant overhead across many fresh ephemeral keys is what rules
      // out any variable-length encoding hiding in the header.
      final Set<int> overheads = <int>{};
      for (int i = 0; i < 10; i++) {
        final Uint8List blob =
            await CryptoService.encrypt(plaintext, keyDuo.encryptionKeyPair);
        overheads.add(blob.length - plaintext.length);
      }

      expect(overheads, hasLength(1),
          reason: 'Overhead must not vary between encryptions');
      expect(
          overheads.single,
          equals(
              CryptoSizes.hybridHeaderLength + CryptoSizes.aesGcmTagLength));
    });
  });

  group('Wire format freshness', () {
    test('each encryption uses a fresh ephemeral key, salt and IV', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final Uint8List plaintext = Uint8List.fromList('same message'.codeUnits);

      final Uint8List first =
          await CryptoService.encrypt(plaintext, keyDuo.encryptionKeyPair);
      final Uint8List second =
          await CryptoService.encrypt(plaintext, keyDuo.encryptionKeyPair);

      expect(Uint8List.sublistView(first, 0, saltOffset),
          isNot(equals(Uint8List.sublistView(second, 0, saltOffset))),
          reason: 'Ephemeral key must not be reused across encryptions');
      expect(Uint8List.sublistView(first, saltOffset, ivOffset),
          isNot(equals(Uint8List.sublistView(second, saltOffset, ivOffset))),
          reason: 'HKDF salt must be random per encryption');
      expect(Uint8List.sublistView(first, ivOffset, ciphertextOffset),
          isNot(equals(
              Uint8List.sublistView(second, ivOffset, ciphertextOffset))),
          reason: 'AES-GCM IV must never repeat under the same key');
      expect(Uint8List.sublistView(first, ciphertextOffset),
          isNot(equals(Uint8List.sublistView(second, ciphertextOffset))),
          reason: 'Encrypting the same plaintext twice must not be detectable');
    });
  });

  group('Wire format tamper detection', () {
    late KeyDuo keyDuo;
    late Uint8List blob;

    setUp(() async {
      keyDuo = await GenerationService.generateKeyDuo();
      blob = await CryptoService.encrypt(
          Uint8List.fromList('confidential'.codeUnits),
          keyDuo.encryptionKeyPair);
    });

    test('flipping a bit in the ephemeral key is rejected', () async {
      // Lands off the curve, so the key never imports at all.
      final Uint8List tampered = Uint8List.fromList(blob)..[40] ^= 0x01;
      await expectLater(
          CryptoService.decrypt(tampered, keyDuo.encryptionKeyPair),
          throwsA(isA<FormatException>()),
          reason: 'An off-curve ephemeral key must be refused, not used');
    });

    test('replacing the ephemeral key tag is rejected', () async {
      final Uint8List tampered = Uint8List.fromList(blob)..[0] = 0x02;
      await expectLater(
          CryptoService.decrypt(tampered, keyDuo.encryptionKeyPair),
          throwsA(isA<FormatException>()),
          reason: 'Only the uncompressed SEC1 tag is accepted on the wire');
    });

    test('flipping a bit in the salt is rejected', () async {
      // Derives a different AES key, so GCM authentication fails.
      final Uint8List tampered = Uint8List.fromList(blob)..[saltOffset] ^= 0x01;
      await expectLater(
          CryptoService.decrypt(tampered, keyDuo.encryptionKeyPair),
          throwsA(anything),
          reason: 'The salt is authenticated in effect: changing it breaks the key');
    });

    test('flipping a bit in the IV is rejected', () async {
      final Uint8List tampered = Uint8List.fromList(blob)..[ivOffset] ^= 0x01;
      await expectLater(
          CryptoService.decrypt(tampered, keyDuo.encryptionKeyPair),
          throwsA(anything),
          reason: 'AES-GCM must not authenticate under the wrong IV');
    });

    test('flipping a bit in the ciphertext is rejected', () async {
      final Uint8List tampered = Uint8List.fromList(blob)
        ..[ciphertextOffset] ^= 0x01;
      await expectLater(
          CryptoService.decrypt(tampered, keyDuo.encryptionKeyPair),
          throwsA(anything),
          reason: 'AES-GCM must detect ciphertext modification');
    });

    test('truncating the blob is rejected', () async {
      for (final int length in <int>[
        0,
        1,
        CryptoSizes.ecP256Sec1PublicKeyLength,
        ciphertextOffset,
        ciphertextOffset + CryptoSizes.aesGcmTagLength - 1,
      ]) {
        await expectLater(
            CryptoService.decrypt(
                Uint8List.sublistView(blob, 0, length),
                keyDuo.encryptionKeyPair),
            throwsA(isA<FormatException>()),
            reason: 'A blob of $length bytes cannot be well formed');
      }
    });

    test('appending trailing bytes is rejected', () async {
      final Uint8List extended = Uint8List(blob.length + 4)..setRange(0, blob.length, blob);
      await expectLater(
          CryptoService.decrypt(extended, keyDuo.encryptionKeyPair),
          throwsA(anything),
          reason: 'Trailing bytes land inside the authenticated ciphertext');
    });
  });

  group('Symmetric wire format', () {
    test('layout is IV + ciphertext + tag and truncation is rejected',
        () async {
      final SymmetricKey key = await GenerationService.generateSymmetricKey();
      final Uint8List plaintext = Uint8List.fromList('symmetric data'.codeUnits);

      final Uint8List blob =
          await CryptoService.encryptSymmetric(plaintext, key);
      expect(
          blob.length,
          equals(CryptoSizes.aesGcmIvLength +
              plaintext.length +
              CryptoSizes.aesGcmTagLength),
          reason: 'Symmetric blobs are IV followed by ciphertext and tag');
      expect(await CryptoService.decryptSymmetric(blob, key), equals(plaintext));

      await expectLater(
          CryptoService.decryptSymmetric(Uint8List(4), key),
          throwsA(isA<FormatException>()),
          reason:
              'Too-short input is a malformed encoding, reported like every '
              'other malformed encoding in this library');
    });
  });

  group('Round trip', () {
    test('survives empty, small and large payloads', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();

      for (final int length in <int>[0, 1, 15, 16, 4096]) {
        final Uint8List plaintext =
            Uint8List.fromList(List<int>.generate(length, (int i) => i % 256));
        final Uint8List blob =
            await CryptoService.encrypt(plaintext, keyDuo.encryptionKeyPair);
        expect(
            await CryptoService.decrypt(blob, keyDuo.encryptionKeyPair),
            equals(plaintext),
            reason: 'Round trip must hold for a $length-byte payload');
      }
    });

    test('string helpers round trip through base64', () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      const String message = 'unicode: café — 日本語';

      final String encoded =
          await CryptoService.encryptString(message, keyDuo.encryptionKeyPair);
      expect(
          await CryptoService.decryptString(encoded, keyDuo.encryptionKeyPair),
          equals(message));
    });
  });
}
