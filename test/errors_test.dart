import 'dart:convert';
import 'dart:typed_data';
import 'package:dart_jwk_duo/dart_jwk_duo.dart';
import 'package:test/test.dart';

void main() {
  test('a JWK Set with "use": 5 throws FormatException', () async {
    final KeyDuo duo = await GenerationService.generateKeyDuo();
    final String json = await const KeyDuoSerializer().exportKeyDuoJwk(duo);
    final Map<String, dynamic> set = jsonDecode(json) as Map<String, dynamic>;
    ((set['keys'] as List<dynamic>)[0] as Map<String, dynamic>)['use'] = 5;
    await expectLater(
        const KeyDuoSerializer().importKeyDuoJwk(jsonEncode(set)), throwsFormatException);
  });

  test('non-object JSON throws FormatException, not TypeError', () async {
    await expectLater(const KeyDuoSerializer().importKeyDuoJwk('[1]'), throwsFormatException);
    await expectLater(const KeyDuoSerializer().importKeyDuoJwk('"x"'), throwsFormatException);
  });

  test('decrypt with a public-only pair throws StateError', () async {
    final KeyDuo duo = await GenerationService.generateKeyDuo();
    final EncryptionKeyPair pub = await EncryptionKeyPair.importPublicKeySec1Hex(
        EncryptionPublicKeyHex(await duo.encryptionKeyPair.exportPublicKeySec1Hex()));
    final Uint8List blob = await CryptoService.encrypt(Uint8List.fromList(<int>[1, 2, 3]), pub);
    await expectLater(CryptoService.decrypt(blob, pub), throwsStateError);
  });

  test('KeyDuo with the same public key in both halves throws ArgumentError', () async {
    final KeyDuo duo = await GenerationService.generateKeyDuo();
    final EncryptionKeyPair e = await EncryptionKeyPair.importPublicKeyRaw(
        await duo.signingKeyPair.exportPublicKeyRaw());
    expect(() => KeyDuo(signing: duo.signingKeyPair, encryption: e), throwsArgumentError);
  });

  test('a Rust-originated argument error maps to ArgumentError', () async {
    await expectLater(
        calculateJwkThumbprint(<String, dynamic>{'crv': 'P-256'}),
        throwsA(isA<ArgumentError>().having(
            (e) => e.message, 'message', contains('kty is required'))));
  });

  test('PublicKeyDuo with equal halves throws ArgumentError', () {
    final String hex = '04${'ab' * 64}';
    expect(
        () => PublicKeyDuo(
            signing: SigningPublicKeyHex(hex), encryption: EncryptionPublicKeyHex(hex)),
        throwsArgumentError);
  });
}
