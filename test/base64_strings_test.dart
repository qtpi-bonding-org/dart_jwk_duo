import 'dart:convert';
import 'dart:typed_data';
import 'package:dart_jwk_duo/dart_jwk_duo.dart';
import 'package:test/test.dart';

/// Ciphertext strings are encoded and decoded by Rust (base64ct): padded
/// standard base64 only. dart:convert would accept the URL-safe alphabet.
void main() {
  late KeyDuo duo;
  setUp(() async => duo = await GenerationService.generateKeyDuo());
  tearDown(() => duo.dispose());

  /// A ciphertext whose standard base64 contains both '+' and '/' somewhere is
  /// rare, so search for one that has at least one of them.
  Future<String> withSpecialChars() async {
    for (int i = 0; i < 500; i++) {
      final String c = await CryptoService.encryptString('m$i', duo.encryptionKeyPair);
      if (c.contains('+') || c.contains('/')) return c;
    }
    fail('no ciphertext with +// found in 500 tries');
  }

  test('round trip, padded standard base64', () async {
    final String c = await CryptoService.encryptString('héllo', duo.encryptionKeyPair,
        info: Uint8List.fromList(<int>[1]), aad: Uint8List.fromList(<int>[2]));
    expect(base64.decode(c), isNotEmpty);
    expect(
        await CryptoService.decryptString(c, duo.encryptionKeyPair,
            info: Uint8List.fromList(<int>[1]), aad: Uint8List.fromList(<int>[2])),
        'héllo');
    expect(await duo.decryptString(await duo.encryptString('x')), 'x');
  });

  test('URL-safe alphabet is rejected', () async {
    final String c = await withSpecialChars();
    final String urlSafe = c.replaceAll('+', '-').replaceAll('/', '_');
    expect(urlSafe, isNot(c));
    expect(await CryptoService.decryptString(c, duo.encryptionKeyPair), isNotEmpty); // control
    await expectLater(CryptoService.decryptString(urlSafe, duo.encryptionKeyPair), throwsFormatException);
    await expectLater(duo.decryptString(urlSafe), throwsFormatException);
  });

  test('unpadded input is rejected', () async {
    String c = await CryptoService.encryptString('a', duo.encryptionKeyPair);
    while (!c.endsWith('=')) {
      c = await CryptoService.encryptString('a' * (1 + c.length % 3), duo.encryptionKeyPair);
    }
    final String unpadded = c.replaceAll('=', '');
    await expectLater(CryptoService.decryptString(unpadded, duo.encryptionKeyPair), throwsFormatException);
    await expectLater(duo.decryptString(unpadded), throwsFormatException);
  });
}
