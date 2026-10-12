import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_jwk_duo/dart_jwk_duo.dart';

/// Generates a key duo, round-trips it through a JWK Set, signs, and encrypts.
Future<void> main() async {
  final KeyDuo duo = await GenerationService.generateKeyDuo();
  const KeyDuoSerializer serializer = KeyDuoSerializer();

  final String jwkSet = await serializer.exportKeyDuoJwk(duo);
  final KeyDuo restored = await serializer.importKeyDuoJwk(jwkSet);

  final Uint8List message = Uint8List.fromList(utf8.encode('hello'));
  final Uint8List signature = await restored.sign(message);
  // ignore: avoid_print
  print('signature valid: ${await duo.verifySignature(message, signature)}');

  final Uint8List blob = await duo.encrypt(message);
  // ignore: avoid_print
  print('decrypted: ${utf8.decode(await restored.decrypt(blob))}');

  duo.dispose();
  restored.dispose();
}
