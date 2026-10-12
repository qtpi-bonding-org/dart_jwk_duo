import 'dart:convert';
import 'package:dart_jwk_duo/dart_jwk_duo.dart';
import 'package:test/test.dart';

Matcher formatMessage(Pattern p) =>
    throwsA(isA<FormatException>().having((FormatException e) => e.message, 'message', contains(p)));

void main() {
  late Map<String, dynamic> privateSet;
  late Map<String, dynamic> publicSet;

  setUp(() async {
    final KeyDuo duo = await GenerationService.generateKeyDuo();
    privateSet = jsonDecode(await const KeyDuoSerializer().exportKeyDuoJwk(duo)) as Map<String, dynamic>;
    publicSet = jsonDecode(await const KeyDuoSerializer().exportPublicKeyDuoJwk(duo)) as Map<String, dynamic>;
    duo.dispose();
  });

  Map<String, dynamic> key(Map<String, dynamic> set, int i) =>
      Map<String, dynamic>.from((set['keys'] as List<dynamic>)[i] as Map<String, dynamic>);

  test('validateKeyDuoJwkStructure', () async {
    await ValidationService.validateKeyDuoJwkStructure(privateSet);
    await expectLater(
        ValidationService.validateKeyDuoJwkStructure(<String, dynamic>{'keys': <dynamic>[]}), throwsFormatException);
  });

  test('validateEcdsaKey', () async {
    await ValidationService.validateEcdsaKey(key(privateSet, 0), requirePrivateKey: true);
    await expectLater(ValidationService.validateEcdsaKey(key(publicSet, 0), requirePrivateKey: true), throwsFormatException);
  });

  test('validateEcdhKey', () async {
    await ValidationService.validateEcdhKey(key(privateSet, 1), requirePrivateKey: true);
    await expectLater(ValidationService.validateEcdhKey(key(publicSet, 1), requirePrivateKey: true), throwsFormatException);
  });

  test('validateSymmetricKeyJwk', () async {
    final SymmetricKey k = await GenerationService.generateSymmetricKey();
    final Map<String, dynamic> jwk = jsonDecode(await k.toJwk()) as Map<String, dynamic>;
    k.dispose();
    await ValidationService.validateSymmetricKeyJwk(jwk);
    await expectLater(ValidationService.validateSymmetricKeyJwk(<String, dynamic>{...jwk}..remove('k')), throwsFormatException);
  });

  test('bug 4: a non-string "use" in a Map argument is a FormatException', () async {
    final Map<String, dynamic> bad = <String, dynamic>{...key(privateSet, 0), 'use': 5};
    await expectLater(ValidationService.validateEcdsaKey(bad, requirePrivateKey: true), throwsFormatException);
  });

  test('extractPublicKeyFields drops private members', () {
    final Map<String, dynamic> out = ValidationService.extractPublicKeyFields(key(privateSet, 0));
    expect(out.containsKey('d'), isFalse);
    expect(out.keys, containsAll(<String>['kty', 'crv', 'x', 'y', 'kid']));
    expect(ValidationService.extractPublicKeyFields(<String, dynamic>{'d': 'x'}), isEmpty);
  });

  test('extractPublicKeySet', () async {
    final Map<String, dynamic> out = await ValidationService.extractPublicKeySet(privateSet);
    expect(jsonEncode(out), isNot(contains('"d"')));
    expect(out['keys'], hasLength(2));
    await expectLater(ValidationService.extractPublicKeySet(<String, dynamic>{'keys': 5}), throwsFormatException);
  });

  test('validateNoPrivateKeyMaterial', () async {
    await ValidationService.validateNoPrivateKeyMaterial(publicSet);
    await expectLater(ValidationService.validateNoPrivateKeyMaterial(privateSet), throwsFormatException);
  });

  test('bug 8: validateNoPrivateKeyMaterial rejects a non-list keys and a non-object key', () async {
    await expectLater(ValidationService.validateNoPrivateKeyMaterial(<String, dynamic>{'keys': <String, dynamic>{}}),
        formatMessage('keys'));
    await expectLater(ValidationService.validateNoPrivateKeyMaterial(<String, dynamic>{'keys': <dynamic>[5]}),
        formatMessage('object'));
  });

  test('validateKeyDuoJwk', () async {
    await ValidationService.validateKeyDuoJwk(jsonEncode(privateSet));
    await expectLater(ValidationService.validateKeyDuoJwk('not json'), throwsFormatException);
  });

  test('validateSymmetricKeyJwkString', () async {
    final SymmetricKey k = await GenerationService.generateSymmetricKey();
    final String jwk = await k.toJwk();
    k.dispose();
    await ValidationService.validateSymmetricKeyJwkString(jwk);
    await expectLater(ValidationService.validateSymmetricKeyJwkString('{"kty":"oct"}'), throwsFormatException);
  });

  test('encodeJsonArg turns a non-JSON value into FormatException', () async {
    await expectLater(
        ValidationService.validateKeyDuoJwkStructure(<String, dynamic>{'keys': Object()}), formatMessage('JSON'));
  });
}
