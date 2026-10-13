import 'dart:io';
import 'dart:isolate';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart' show ExternalLibrary;
import 'bridge/frb_generated.dart';

Future<void>? _init;

/// Loads the native rust_jwk_duo library once. Every public entry point that
/// touches the bridge awaits this first. Concurrent first calls share one
/// load; a failed load is not cached, so a later call retries.
Future<void> ensureInitialized() => _init ??= _loadOnce();

Future<void> _loadOnce() async {
  try {
    await _load();
  } catch (_) {
    _init = null;
    rethrow;
  }
}

Future<void> _load() async {
  final String? override = Platform.environment['DART_JWK_DUO_NATIVE_LIB'];
  if (override != null) {
    await JwkDuoRust.init(externalLibrary: ExternalLibrary.open(override));
  } else if (Platform.isMacOS || Platform.isLinux) {
    // dart test / dart run: use the build hook's output, as episutra does.
    // Inside a Flutter app the hook output cannot be located this way (see below).
    File? lib;
    try {
      lib = _hookOutput();
    } on UnsupportedError {
      // Isolate.resolvePackageUriSync is unsupported under the Flutter engine
      // (a packaged macOS app, flutter_tester), where there is no hook output
      // to find. Fall back to FRB's default loading, which finds the library
      // the app bundles.
      lib = null;
    }
    await JwkDuoRust.init(externalLibrary: lib == null ? null : ExternalLibrary.open(lib.path));
  } else {
    await JwkDuoRust.init(); // packaged app: FRB's default loading (verified on iOS simulator and Android emulator, x86_64)
  }
}

File? _hookOutput() {
  final String name = Platform.isMacOS ? 'libdart_jwk_duo_bridge.dylib' : 'libdart_jwk_duo_bridge.so';
  // Resolve against the package root, not the current directory, so it works
  // from any working directory and from dependent packages' tests.
  final Uri? libDir = Isolate.resolvePackageUriSync(Uri.parse('package:dart_jwk_duo/'));
  final Uri pkgRoot = libDir == null ? Directory.current.uri : libDir.resolve('../');
  for (final String rel in <String>['rust/target/native-assets/', '.dart_tool/']) {
    final Directory dir = Directory.fromUri(pkgRoot.resolve(rel));
    if (!dir.existsSync()) continue;
    for (final File f in dir.listSync(recursive: true, followLinks: false).whereType<File>()) {
      if (f.uri.pathSegments.last == name) return f;
    }
  }
  return null;
}
