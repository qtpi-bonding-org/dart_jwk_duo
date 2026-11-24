/// Web self check, driven by tool/web_conformance.dart (headless Chrome).
library;

import 'dart:convert';
import 'dart:js_interop';
import 'package:dart_jwk_duo/dart_jwk_duo.dart';
import 'package:dart_jwk_duo/testing.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

@JS('fetch')
external JSPromise<_Response> _fetch(String url, [_Options? options]);

extension type _Options._(JSObject _) implements JSObject {
  external factory _Options({String method, String body});
}

extension type _Response._(JSObject _) implements JSObject {
  external JSPromise<JSString> text();
}

@JS('crossOriginIsolated')
external bool get _crossOriginIsolated;

@JS('crypto.getRandomValues')
external JSFunction get _getRandomValues;
@JS('crypto.getRandomValues')
external set _getRandomValues(JSFunction f);

JSAny? _noRng(JSAny? _) => throw StateError('no rng');

Future<String> _get(String url) async => (await (await _fetch(url).toDart).text().toDart).toDart;

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final Map<String, Object?> report = <String, Object?>{};
  try {
    await _run(report);
  } catch (e, st) {
    report['error'] = '$e\n$st';
  }
  await _fetch('report', _Options(method: 'POST', body: jsonEncode(report))).toDart;
}

Future<String> _thrown(Future<Object?> Function() f, {bool detail = false}) async {
  try {
    await f();
  } catch (e) {
    // Not runtimeType: release builds minify it.
    return switch (e) {
      StateError(:final String message) => detail ? 'StateError: $message' : 'StateError',
      FormatException() => 'FormatException',
      _ => 'other: $e',
    };
  }
  return 'nothing';
}

Future<void> _run(Map<String, Object?> report) async {
  report['crossOriginIsolated'] = _crossOriginIsolated;
  // The server breaks the first three loads: script 404, HTML instead of the
  // script, wasm 404. Each must fail, and none may be cached.
  report['loadFailures'] = <String>[for (int i = 0; i < 3; i++) await _thrown(ensureInitialized)];
  await Future.wait(<Future<void>>[ensureInitialized(), ensureInitialized(), ensureInitialized()]);

  final List<String> files = (await AssetManifest.loadFromAssetBundle(rootBundle))
      .listAssets()
      .where((String a) => a.startsWith('assets/conformance/') && a.endsWith('.json'))
      .map((String a) => a.substring('assets/conformance/'.length))
      .toList();
  final ConformanceReport c =
      await runConformance(load: (String p) => rootBundle.loadString('assets/conformance/$p'), files: files);
  report['conformance'] = <String, Object>{
    'files': c.files.length,
    'run': c.run,
    'passed': c.passed,
    'skipped': c.skipped,
    'failures': c.failures,
  };

  report['interopChecks'] = await checkInteropBundle(await _get('interop.json'));
  report['interopBundle'] = await createInteropBundle();

  final KeyDuo a = await GenerationService.generateKeyDuo();
  final KeyDuo b = await GenerationService.generateKeyDuo();
  report['distinctKeys'] =
      (await a.exportPublicKeyDuo()).signing.value != (await b.exportPublicKeyDuo()).signing.value;
  report['verifyKeyDuo'] = await VerificationService.verifyKeyDuo(a);
  a.dispose();
  report['useAfterDispose'] = await _thrown(() => a.signingKeyPair.calculateKeyId());
  report['badInput'] = await _thrown(() => CryptoService.decrypt(Uint8List(3), b.encryptionKeyPair));

  // Last: without the browser RNG, key generation must fail, not fall back.
  final JSFunction original = _getRandomValues;
  _getRandomValues = _noRng.toJS;
  report['noRng'] = await _thrown(GenerationService.generateKeyDuo, detail: true);
  _getRandomValues = original;
  report['afterPanic'] = await _thrown(GenerationService.generateKeyDuo, detail: true);
}
