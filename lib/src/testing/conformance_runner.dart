/// Runs the rust_jwk_duo conformance vectors through the Dart public API.
library;

import 'dart:convert';
import 'dart:typed_data';
import '../bridge/api.dart' as r;
import '../crypto_service.dart';
import '../hex_codec.dart';
import '../init.dart';
import '../jwk_thumbprint.dart';
import '../key_duo.dart';
import '../key_duo_serializer.dart';
import '../public_key_hex.dart';
import '../sec1_public_key.dart';
import '../signing_key_pair.dart';
import '../symmetric_key.dart';

/// Exact case count per file. A truncated, emptied or extended file fails.
/// Mirrors the FILES table in rust_jwk_duo/tests/conformance_cases.rs.
const Map<String, int> _expectedCases = <String, int>{
  'jwk_duo/hex.json': 8,
  'jwk_duo/sec1.json': 9,
  'jwk_duo/public_key_duo.json': 10,
  'jwk_duo/thumbprint.json': 11,
  'jwk_duo/jwk_set_valid.json': 4,
  'jwk_duo/jwk_set_invalid.json': 35,
  'jwk_duo/exported_jwk.json': 8,
  'jwk_duo/signature_verify.json': 10,
  'jwk_duo/hpke_open.json': 19,
  'jwk_duo/symmetric_open.json': 16,
  'wycheproof/ecdsa_secp256r1_sha256_p1363_test.json': 262,
};

/// Ops the README marks Rust-only: Dart 3.0 has no public `ExportedJwk`
/// constructor. They are counted as skipped, never as passed.
const Set<String> _rustOnlyOps = <String>{'exported_jwk.check'};

const String _wycheproofP1363 = 'wycheproof/ecdsa_secp256r1_sha256_p1363_test.json';

/// The outcome of [runConformance].
class ConformanceReport {
  ConformanceReport._(this.files, this.failures, this.skippedOps);

  /// Per file: cases that ran (passed or failed), passed, and skipped.
  /// `run + skipped` equals the file's case count when the file loaded.
  final Map<String, ({int run, int passed, int skipped})> files;

  /// One human-readable line per failure. Empty when everything conformed.
  final List<String> failures;

  /// The distinct ops that were skipped.
  final Set<String> skippedOps;

  /// Cases that ran and matched.
  int get passed => files.values.fold(0, (int a, ({int passed, int run, int skipped}) f) => a + f.passed);

  /// Cases that ran, passed or not.
  int get run => files.values.fold(0, (int a, ({int passed, int run, int skipped}) f) => a + f.run);

  /// Cases skipped because their op is Rust-only.
  int get skipped => files.values.fold(0, (int a, ({int passed, int run, int skipped}) f) => a + f.skipped);
}

/// Runs the rust_jwk_duo conformance cases through the Dart public API.
/// [load] reads a file relative to the conformance directory, so the same
/// runner works from `dart test` (File) and inside an app (rootBundle).
///
/// Never throws for a conformance mismatch: every problem lands in
/// [ConformanceReport.failures].
Future<ConformanceReport> runConformance({
  required Future<String> Function(String relPath) load,
  required List<String> files,
}) async {
  await ensureInitialized();
  final Map<String, ({int run, int passed, int skipped})> perFile =
      <String, ({int run, int passed, int skipped})>{};
  final List<String> failures = <String>[];
  final Set<String> skippedOps = <String>{};

  for (final String file in files) {
    final _Counter c = _Counter();
    try {
      final Object? doc = jsonDecode(await load(file));
      if (doc is! Map<String, dynamic>) {
        failures.add('$file: top level must be an object');
      } else if (file == _wycheproofP1363) {
        await _runWycheproof(file, doc, c, failures);
      } else {
        await _runCaseFile(file, doc, c, failures, skippedOps);
      }
    } catch (e) {
      failures.add('$file: could not load or parse: $e');
    }
    perFile[file] = (run: c.run, passed: c.passed, skipped: c.skipped);
  }
  return ConformanceReport._(perFile, failures, skippedOps);
}

class _Counter {
  int run = 0;
  int passed = 0;
  int skipped = 0;
}

Future<void> _runCaseFile(String file, Map<String, dynamic> doc, _Counter c,
    List<String> failures, Set<String> skippedOps) async {
  final int? want = _expectedCases[file];
  if (want == null) {
    failures.add('$file: no expected case count registered for this file');
    return;
  }
  if (doc['format_version'] != r.formatVersion()) {
    failures.add('$file: format_version ${doc['format_version']} != ${r.formatVersion()}');
    return;
  }
  final Object? cases = doc['cases'];
  if (cases is! List<dynamic>) {
    failures.add('$file: cases must be an array');
    return;
  }
  if (cases.length != want) {
    failures.add('$file: case count ${cases.length} != expected $want (truncated or extended file)');
    return;
  }

  final Set<String> ids = <String>{};
  for (final Object? raw in cases) {
    final Map<String, dynamic> cs = raw as Map<String, dynamic>;
    final String id = cs['id'] as String;
    final String where = '$file/$id';
    if (!ids.add(id)) {
      failures.add('$where: duplicate id');
      c.run++;
      continue;
    }
    // A case-level op wins over the file's.
    final Object? op = cs['op'] ?? doc['op'];
    if (op is! String) {
      failures.add('$where: no op');
      c.run++;
      continue;
    }
    if (_rustOnlyOps.contains(op)) {
      c.skipped++;
      skippedOps.add(op);
      continue;
    }
    c.run++;
    final String? problem = await _runCase(op, cs);
    if (problem == null) {
      c.passed++;
    } else {
      failures.add('$where ($op): $problem');
    }
  }
}

/// Runs one case. Returns null on conformance, else the reason.
Future<String?> _runCase(String op, Map<String, dynamic> cs) async {
  final Object? expect = cs['expect'];
  if (expect is! Map<String, dynamic> || expect.length != 1) {
    return 'expect must have exactly one member';
  }
  final Map<String, dynamic> input = cs['input'] as Map<String, dynamic>;

  Object? got;
  Object? thrown;
  try {
    got = await _dispatch(op, input);
  } catch (e) {
    thrown = e;
  }

  if (expect.containsKey('ok')) {
    if (thrown != null) return 'expected ok, got ${thrown.runtimeType}: $thrown';
    return _deepEqual(got, expect['ok']) ? null : 'expected ${jsonEncode(expect['ok'])}, got ${jsonEncode(got)}';
  }
  final Object? wantKind = expect['error'];
  if (wantKind is! String) return 'expect must be {ok} or {error}';
  if (thrown == null) return 'expected error $wantKind, got ok ${jsonEncode(got)}';
  final String? kind = _kindOf(thrown);
  if (kind == null) return 'expected error $wantKind, got unmapped ${thrown.runtimeType}: $thrown';
  return kind == wantKind ? null : 'expected error $wantKind, got $kind ($thrown)';
}

String? _kindOf(Object e) {
  if (e is FormatException) return 'format';
  if (e is StateError) return 'state';
  if (e is ArgumentError) return 'argument';
  return null;
}

String _s(Map<String, dynamic> input, String k) {
  final Object? v = input[k];
  if (v is! String) throw StateError('conformance input member $k must be a string');
  return v;
}

Uint8List _b64(Map<String, dynamic> input, String k) => base64.decode(_s(input, k));

/// Fixture hex: lenient on length, like the Rust runner's `hex()` helper.
Uint8List _fixtureHex(String v) => HexCodec.decode(v, expectedLength: v.length);

Future<Object?> _dispatch(String op, Map<String, dynamic> input) async {
  switch (op) {
    case 'hex.decode':
      return HexCodec.encode(HexCodec.decode(_s(input, 'hex'), expectedLength: input['expected_len'] as int));
    case 'hex.encode':
      return HexCodec.encode(_fixtureHex(_s(input, 'bytes_hex')));
    case 'sec1.decode_hex':
      return HexCodec.encode(Sec1PublicKey.decodeHex(_s(input, 'hex')));
    case 'public_key_duo.from_json':
      // Dart's signature takes a Map, so a non-object cannot reach it; the
      // vectors still require the "not an object" case to be a format error.
      final Object? json = input['json'];
      if (json is! Map<String, dynamic>) {
        throw const FormatException('PublicKeyDuo JSON must be an object');
      }
      return PublicKeyDuo.fromJson(json).toJson();
    case 'thumbprint':
      return await calculateJwkThumbprint(input['jwk'] as Map<String, dynamic>);
    case 'jwk_set.import_private':
      return await _publicDuoJson(await const KeyDuoSerializer().importKeyDuoJwk(_s(input, 'jwk_set')));
    case 'jwk_set.import_public':
      return await _publicDuoJson(await const KeyDuoSerializer().importPublicKeyDuoJwk(_s(input, 'jwk_set')));
    case 'signature.verify':
      final SigningKeyPair key =
          await SigningKeyPair.importPublicKeyRaw(Sec1PublicKey.decodeHex(_s(input, 'public_hex')));
      try {
        return await key.verifyBytes(_fixtureHex(_s(input, 'signature_hex')), _b64(input, 'message_b64'));
      } finally {
        key.dispose();
      }
    case 'crypto.decrypt':
      final KeyDuo duo = await const KeyDuoSerializer().importKeyDuoJwk(_s(input, 'jwk_set'));
      try {
        final Uint8List pt = await CryptoService.decrypt(_b64(input, 'blob_b64'), duo.encryptionKeyPair,
            info: _b64(input, 'info_b64'), aad: _b64(input, 'aad_b64'));
        return base64.encode(pt);
      } finally {
        duo.dispose();
      }
    case 'symmetric.decrypt':
      final SymmetricKey key = await SymmetricKey.fromJwk(_s(input, 'key_jwk'));
      try {
        return base64.encode(
            await CryptoService.decryptSymmetric(_b64(input, 'blob_b64'), key, aad: _b64(input, 'aad_b64')));
      } finally {
        key.dispose();
      }
    default:
      throw StateError('unknown conformance op $op');
  }
}

Future<Map<String, dynamic>> _publicDuoJson(KeyDuo duo) async {
  try {
    return (await duo.exportPublicKeyDuo()).toJson();
  } finally {
    duo.dispose();
  }
}

/// Wycheproof ECDSA P-256 / SHA-256 / P1363. Verdict rules: a key that fails
/// to import is only allowed on `invalid` cases and then the verdict is
/// false; otherwise `verifyBytes` must equal `result == "valid"`. Every case
/// counts (there is no "acceptable" result in this file).
Future<void> _runWycheproof(String file, Map<String, dynamic> doc, _Counter c, List<String> failures) async {
  final int want = _expectedCases[file]!;
  if (doc['numberOfTests'] != want) {
    failures.add('$file: numberOfTests ${doc['numberOfTests']} != expected $want');
    return;
  }
  final Set<int> tcIds = <int>{};
  for (final Object? rawGroup in doc['testGroups'] as List<dynamic>) {
    final Map<String, dynamic> group = rawGroup as Map<String, dynamic>;
    SigningKeyPair? key;
    try {
      key = await SigningKeyPair.importPublicKeyRaw(
          _fixtureHex((group['publicKey'] as Map<String, dynamic>)['uncompressed'] as String));
    } on FormatException {
      key = null;
    }
    try {
      for (final Object? rawTest in group['tests'] as List<dynamic>) {
        final Map<String, dynamic> t = rawTest as Map<String, dynamic>;
        final int tcId = t['tcId'] as int;
        final String where = '$file/tc$tcId (${t['comment']})';
        c.run++;
        if (!tcIds.add(tcId)) {
          failures.add('$where: duplicate tcId');
          continue;
        }
        final String result = t['result'] as String;
        if (result != 'valid' && result != 'invalid') {
          failures.add('$where: unexpected result "$result"');
          continue;
        }
        final bool verdict = key == null
            ? false
            : await key.verifyBytes(_fixtureHex(t['sig'] as String), _fixtureHex(t['msg'] as String));
        if (key == null && result != 'invalid') {
          failures.add('$where: key import failed but case is "$result"');
        } else if (verdict != (result == 'valid')) {
          failures.add('$where: verdict $verdict, vector says $result');
        } else {
          c.passed++;
        }
      }
    } finally {
      key?.dispose();
    }
  }
  if (c.run != want) failures.add('$file: ran ${c.run} cases, expected $want');
}

bool _deepEqual(Object? a, Object? b) {
  if (a is Map && b is Map) {
    if (a.length != b.length) return false;
    for (final Object? k in a.keys) {
      if (!b.containsKey(k) || !_deepEqual(a[k], b[k])) return false;
    }
    return true;
  }
  if (a is List && b is List) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (!_deepEqual(a[i], b[i])) return false;
    }
    return true;
  }
  return a == b;
}
