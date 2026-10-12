import 'package:dart_jwk_duo/dart_jwk_duo.dart';
import 'package:test/test.dart';

// This file must not touch the library before the test body runs: `dart test`
// gives each file its own isolate, so the first use below is a true first use.
void main() {
  test('concurrent first use shares one native load', () async {
    final List<KeyDuo> duos = await Future.wait(<Future<KeyDuo>>[
      GenerationService.generateKeyDuo(),
      GenerationService.generateKeyDuo(),
      GenerationService.generateKeyDuo(),
    ]);
    expect(duos, hasLength(3));
    await ensureInitialized(); // already loaded: completes without a second init
  });

  test('use after dispose is a StateError, not a bridge exception', () async {
    final KeyDuo duo = await GenerationService.generateKeyDuo();
    duo.dispose();
    await expectLater(duo.encryptionKeyPair.calculateKeyId(), throwsStateError);
    expect(() => duo.signingKeyPair.hasPrivateKey, throwsStateError);
  });
}
