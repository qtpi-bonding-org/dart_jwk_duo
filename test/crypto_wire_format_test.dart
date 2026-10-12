/// Tests for the symmetric wire format and encryption round trips.
///
/// The HPKE blob layout (`0x01 || enc || ct || tag`) is pinned by the shared
/// conformance vectors (`hpke_open.json`), not here.
library;

import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dart_jwk_duo/src/constants.dart';
import 'package:dart_jwk_duo/src/crypto_service.dart';
import 'package:dart_jwk_duo/src/generation_service.dart';
import 'package:dart_jwk_duo/src/key_duo.dart';
import 'package:dart_jwk_duo/src/symmetric_key.dart';

void main() {
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

    test('info and aad are bound: same values open, different values fail',
        () async {
      final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
      final Uint8List plaintext = Uint8List.fromList('bound'.codeUnits);
      final Uint8List info = Uint8List.fromList('ctx-info'.codeUnits);
      final Uint8List aad = Uint8List.fromList('ctx-aad'.codeUnits);

      final Uint8List blob = await CryptoService.encrypt(
          plaintext, keyDuo.encryptionKeyPair,
          info: info, aad: aad);
      expect(
          await CryptoService.decrypt(blob, keyDuo.encryptionKeyPair,
              info: info, aad: aad),
          equals(plaintext));
      await expectLater(
          CryptoService.decrypt(blob, keyDuo.encryptionKeyPair, aad: aad),
          throwsA(isA<FormatException>()),
          reason: 'missing info must not open the blob');
      await expectLater(
          CryptoService.decrypt(blob, keyDuo.encryptionKeyPair, info: info),
          throwsA(isA<FormatException>()),
          reason: 'missing aad must not open the blob');
    });

    test('symmetric aad is bound', () async {
      final SymmetricKey key = await GenerationService.generateSymmetricKey();
      final Uint8List plaintext = Uint8List.fromList('sym'.codeUnits);
      final Uint8List aad = Uint8List.fromList('a'.codeUnits);
      final Uint8List blob =
          await CryptoService.encryptSymmetric(plaintext, key, aad: aad);
      expect(await CryptoService.decryptSymmetric(blob, key, aad: aad),
          equals(plaintext));
      await expectLater(CryptoService.decryptSymmetric(blob, key),
          throwsA(isA<FormatException>()));
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
