/// Cross-platform interop bundles: one platform writes, another checks.
library;

import 'dart:convert';
import 'dart:typed_data';
import '../crypto_service.dart';
import '../encryption_key_pair.dart';
import '../generation_service.dart';
import '../hex_codec.dart';
import '../key_duo.dart';
import '../key_duo_serializer.dart';
import '../public_key_hex.dart';
import '../signing_key_pair.dart';
import '../symmetric_key.dart';

final Uint8List _info = utf8.encode('interop info');
final Uint8List _aad = utf8.encode('interop aad');

List<Uint8List> _messages() => <Uint8List>[
      Uint8List(0),
      utf8.encode('interop é\u{1F511}'),
      Uint8List.fromList(List<int>.generate(70000, (int i) => i % 256)),
    ];

/// Makes fresh TEST keys and returns them (private members included) with
/// ciphertexts and signatures as JSON, for [checkInteropBundle] elsewhere.
Future<String> createInteropBundle() async {
  final KeyDuo duo = await GenerationService.generateKeyDuo();
  final SymmetricKey key = await GenerationService.generateSymmetricKey();
  try {
    final List<Map<String, String>> cases = <Map<String, String>>[
      for (final Uint8List m in _messages())
        <String, String>{
          'hpke': base64.encode(await CryptoService.encrypt(m, duo.encryptionKeyPair, info: _info, aad: _aad)),
          'gcm': base64.encode(await CryptoService.encryptSymmetric(m, key, aad: _aad)),
          'sig': HexCodec.encode(await CryptoService.sign(m, duo.signingKeyPair)),
        },
    ];
    return jsonEncode(<String, Object>{
      'privateSet': await const KeyDuoSerializer().exportKeyDuoJwk(duo),
      'publicSet': await const KeyDuoSerializer().exportPublicKeyDuoJwk(duo),
      'publicDuo': (await duo.exportPublicKeyDuo()).toJson(),
      'symmetric': await key.toJwk(),
      'cases': cases,
    });
  } finally {
    duo.dispose();
    key.dispose();
  }
}

/// Imports every key form in [bundle], opens its ciphertexts and verifies its
/// signatures. Returns the number of checks; throws [StateError] on a mismatch.
Future<int> checkInteropBundle(String bundle) async {
  final Map<String, dynamic> b = jsonDecode(bundle) as Map<String, dynamic>;
  int checks = 0;
  void check(bool ok, String what) {
    if (!ok) throw StateError('interop mismatch: $what');
    checks++;
  }

  const KeyDuoSerializer serializer = KeyDuoSerializer();
  final KeyDuo duo = await serializer.importKeyDuoJwk(b['privateSet'] as String);
  final KeyDuo public = await serializer.importPublicKeyDuoJwk(b['publicSet'] as String);
  final PublicKeyDuo hex = PublicKeyDuo.fromJson(b['publicDuo'] as Map<String, dynamic>);
  final SymmetricKey key = await SymmetricKey.fromJwk(b['symmetric'] as String);
  final SigningKeyPair rawSigning = await SigningKeyPair.importPublicKeySec1Hex(hex.signing);
  final EncryptionKeyPair rawEncryption = await EncryptionKeyPair.importPublicKeySec1Hex(hex.encryption);
  try {
    check(await serializer.exportKeyDuoJwk(duo) == b['privateSet'], 'private set re-export');
    check(await serializer.exportPublicKeyDuoJwk(public) == b['publicSet'], 'public set re-export');
    check(await key.toJwk() == b['symmetric'], 'symmetric re-export');
    final List<Uint8List> messages = _messages();
    final List<dynamic> cases = b['cases'] as List<dynamic>;
    check(cases.length == messages.length, 'case count');
    for (int i = 0; i < messages.length; i++) {
      final Uint8List m = messages[i];
      final Map<String, dynamic> c = cases[i] as Map<String, dynamic>;
      bool same(Uint8List got) => HexCodec.encode(got) == HexCodec.encode(m);
      check(
          same(await CryptoService.decrypt(base64.decode(c['hpke'] as String), duo.encryptionKeyPair,
              info: _info, aad: _aad)),
          'hpke $i');
      check(same(await CryptoService.decryptSymmetric(base64.decode(c['gcm'] as String), key, aad: _aad)), 'gcm $i');
      final Uint8List sig = HexCodec.decode(c['sig'] as String, expectedLength: 128);
      check(await rawSigning.verifyBytes(sig, m), 'sig by sec1 key $i');
      check(await public.signingKeyPair.verifyBytes(sig, m), 'sig by jwk key $i');
      check(!await rawSigning.verifyBytes(sig, Uint8List.fromList(<int>[...m, 0])), 'sig rejects $i');
      check(
          same(await CryptoService.decrypt(
              await CryptoService.encrypt(m, rawEncryption, info: _info), duo.encryptionKeyPair,
              info: _info)),
          'hpke to imported key $i');
    }
  } finally {
    duo.dispose();
    public.dispose();
    key.dispose();
    rawSigning.dispose();
    rawEncryption.dispose();
  }
  return checks;
}
