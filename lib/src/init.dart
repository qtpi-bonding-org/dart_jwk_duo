import 'dart:io';
import 'dart:isolate';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart' show ExternalLibrary;
import 'bridge/frb_generated.dart';

bool _initialized = false;

/// Loads the native rust_jwk_duo library once. Every public entry point that
/// touches the bridge awaits this first.
Future<void> ensureInitialized() async {
  if (_initialized) return;
  final override = Platform.environment['DART_JWK_DUO_NATIVE_LIB'];
  if (override != null) {
    await JwkDuoRust.init(externalLibrary: ExternalLibrary.open(override));
  } else if (Platform.isMacOS || Platform.isLinux) {
    // dart test / dart run: use the build hook's output, as episutra does.
    final lib = _hookOutput();
    await JwkDuoRust.init(externalLibrary: lib == null ? null : ExternalLibrary.open(lib.path));
  } else {
    await JwkDuoRust.init(); // packaged app: FRB's default loading (verified in Task 19)
  }
  _initialized = true;
}

File? _hookOutput() {
  final name = Platform.isMacOS ? 'libdart_jwk_duo_bridge.dylib' : 'libdart_jwk_duo_bridge.so';
  // Resolve against the package root, not the current directory, so it works
  // from any working directory and from dependent packages' tests.
  final libDir = Isolate.resolvePackageUriSync(Uri.parse('package:dart_jwk_duo/'));
  final pkgRoot = libDir == null ? Directory.current.uri : libDir.resolve('../');
  for (final rel in ['rust/target/native-assets/', '.dart_tool/']) {
    final dir = Directory.fromUri(pkgRoot.resolve(rel));
    if (!dir.existsSync()) continue;
    for (final f in dir.listSync(recursive: true, followLinks: false).whereType<File>()) {
      if (f.uri.pathSegments.last == name) return f;
    }
  }
  return null;
}
