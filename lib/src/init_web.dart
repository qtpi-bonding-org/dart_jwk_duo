import 'dart:async';
import 'dart:js_interop';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart' show ExternalLibrary;
// The web class, which the analyzer (it sees the native one) cannot resolve
// through the public import. flutter_rust_bridge is pinned to an exact version.
// ignore: implementation_imports
import 'package:flutter_rust_bridge/src/platform_types/_web.dart' as web;
import 'bridge/frb_generated.dart';

/// The wasm-bindgen module, published under this name by bin/build_web.dart.
@JS('globalThis.dartJwkDuoBridge')
external _WasmBindgen? get _module;

/// The fixed global flutter_rust_bridge's web binding calls through.
@JS('globalThis.wasm_bindgen')
external JSAny? get _frbGlobal;
@JS('globalThis.wasm_bindgen')
external set _frbGlobal(JSAny? value);

extension type _WasmBindgen._(JSFunction _) implements JSFunction {}

@JS('globalThis.dartJwkDuoBridge')
external JSPromise<JSAny?> _instantiate(_InitOptions options);

extension type _InitOptions._(JSObject _) implements JSObject {
  // ignore: non_constant_identifier_names
  external factory _InitOptions({String module_or_path});
}

@JS('document')
external _Document get _document;

extension type _Document._(JSObject _) implements JSObject {
  external String get baseURI;
  external _Script createElement(String name);
  external _Head get head;
}

extension type _Head._(JSObject _) implements JSObject {
  external void appendChild(_Script node);
}

extension type _Script._(JSObject _) implements JSObject {
  external set src(String value);
  external set onload(JSFunction? value);
  external set onerror(JSFunction? value);
  external void remove();
}

/// Loads `pkg/dart_jwk_duo_bridge.js` and its wasm, relative to the page's base
/// URL. Platform half of `ensureInitialized`.
///
/// Does not use flutter_rust_bridge's own web loader: that one waits forever
/// when the script is missing and needs `eval`, which a CSP may forbid.
Future<void> loadBridge() async {
  final Uri root = Uri.parse(_document.baseURI).resolve('pkg/dart_jwk_duo_bridge');
  if (_module == null) await _loadScript('$root.js');
  final _WasmBindgen? module = _module;
  if (module == null) {
    // For example a server that answers a missing file with index.html.
    throw StateError('$root.js is not the dart_jwk_duo web build. $_hint');
  }
  final JSAny? other = _frbGlobal;
  if (other != null && !other.strictEquals(module).toDart) {
    throw StateError('Another wasm-bindgen module already owns window.wasm_bindgen. '
        'flutter_rust_bridge supports one such library per page.');
  }
  _frbGlobal = module;
  try {
    await _instantiate(_InitOptions(module_or_path: '${root}_bg.wasm')).toDart;
  } catch (e) {
    throw StateError('Could not load ${root}_bg.wasm: $e. $_hint');
  }
  final Object library = web.ExternalLibrary(debugInfo: 'moduleRoot=$root');
  await JwkDuoRust.init(externalLibrary: library as ExternalLibrary);
}

const String _hint = 'Run `dart run dart_jwk_duo:build_web` in the app before building it.';

Future<void> _loadScript(String url) async {
  final Completer<void> done = Completer<void>();
  final _Script script = _document.createElement('script');
  script.src = url;
  script.onload = ((JSAny? _) => done.complete()).toJS;
  script.onerror = ((JSAny? _) => done.completeError(StateError('Could not load $url. $_hint'))).toJS;
  _document.head.appendChild(script);
  try {
    await done.future;
  } finally {
    script.remove();
  }
}
