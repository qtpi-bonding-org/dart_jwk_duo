/// Runs the rust_jwk_duo conformance vectors through the Dart API.
///
/// The vectors are read from the sibling rust_jwk_duo repo (never copied):
/// `JWK_DUO_CONFORMANCE_DIR`, default `../rust_jwk_duo/conformance`.
library;

import 'dart:io';
import 'package:dart_jwk_duo/testing.dart';
import 'package:test/test.dart';

const List<String> _files = <String>[
  'jwk_duo/hex.json',
  'jwk_duo/sec1.json',
  'jwk_duo/public_key_duo.json',
  'jwk_duo/thumbprint.json',
  'jwk_duo/jwk_set_valid.json',
  'jwk_duo/jwk_set_invalid.json',
  'jwk_duo/exported_jwk.json',
  'jwk_duo/signature_verify.json',
  'jwk_duo/hpke_open.json',
  'jwk_duo/symmetric_open.json',
  'wycheproof/ecdsa_secp256r1_sha256_p1363_test.json',
];

/// (cases run, cases skipped) per file; the sum is the file's case count.
const Map<String, (int, int)> _runSkipped = <String, (int, int)>{
  'jwk_duo/hex.json': (8, 0),
  'jwk_duo/sec1.json': (9, 0),
  'jwk_duo/public_key_duo.json': (10, 0),
  'jwk_duo/thumbprint.json': (11, 0),
  'jwk_duo/jwk_set_valid.json': (4, 0),
  'jwk_duo/jwk_set_invalid.json': (35, 0),
  'jwk_duo/exported_jwk.json': (0, 8), // exported_jwk.check is Rust-only
  'jwk_duo/signature_verify.json': (10, 0),
  'jwk_duo/hpke_open.json': (19, 0),
  'jwk_duo/symmetric_open.json': (16, 0),
  'wycheproof/ecdsa_secp256r1_sha256_p1363_test.json': (262, 0),
};

void main() {
  final String dir =
      Platform.environment['JWK_DUO_CONFORMANCE_DIR'] ?? '../rust_jwk_duo/conformance';
  Future<String> load(String p) => File('$dir/$p').readAsString();

  test('every jwk_duo case file on disk is wired into the runner', () {
    final List<String> onDisk = Directory('$dir/jwk_duo')
        .listSync()
        .whereType<File>()
        .map((File f) => 'jwk_duo/${f.uri.pathSegments.last}')
        .where((String n) => n.endsWith('.json'))
        .toList()
      ..sort();
    final List<String> wired = _files.where((String f) => f.startsWith('jwk_duo/')).toList()..sort();
    expect(onDisk, equals(wired));
  });

  test('all conformance cases conform; only Rust-only ops are skipped', () async {
    final ConformanceReport report = await runConformance(load: load, files: _files);

    expect(report.failures, isEmpty, reason: report.failures.join('\n'));

    for (final String f in _files) {
      final (int run, int skipped) = _runSkipped[f]!;
      final ({int passed, int run, int skipped})? r = report.files[f];
      expect(r, isNotNull, reason: f);
      expect((r!.run, r.skipped), equals((run, skipped)), reason: '$f run/skipped');
      expect(r.passed, equals(run), reason: '$f passed');
    }
    expect(report.files.keys.toSet(), equals(_files.toSet()));
    expect(report.run, equals(384));
    expect(report.passed, equals(384));
    expect(report.skipped, equals(8));
    expect(report.skippedOps, equals(<String>{'exported_jwk.check'}));
  });
}
