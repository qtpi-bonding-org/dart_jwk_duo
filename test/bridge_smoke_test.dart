import 'dart:convert';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dart_jwk_duo/src/init.dart';
import 'package:dart_jwk_duo/src/bridge/api.dart' as r;

void main() {
  setUpAll(ensureInitialized);
  test('HPKE round trip through the bridge, and context binding holds', () {
    final r.RDuoParts duo = r.generateKeyDuo();
    final Uint8List pt = Uint8List.fromList(utf8.encode('bridge'));
    final Uint8List info = Uint8List.fromList(utf8.encode('i'));
    final Uint8List blob = r.hpkeEncrypt(data: pt, recipient: duo.encryption, info: info, aad: Uint8List(0));
    expect(r.hpkeDecrypt(data: blob, recipient: duo.encryption, info: info, aad: Uint8List(0)), pt);
    expect(() => r.hpkeDecrypt(data: blob, recipient: duo.encryption, info: Uint8List(0), aad: Uint8List(0)), throwsA(isA<r.RError>()));
    expect(r.formatVersion(), 1);
  });
}
