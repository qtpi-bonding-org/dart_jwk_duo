import 'init_io.dart' if (dart.library.js_interop) 'init_web.dart';

Future<void>? _init;

/// Loads the rust_jwk_duo library (native, or wasm on the web) once. Every public entry point that
/// touches the bridge awaits this first. Concurrent first calls share one
/// load; a failed load is not cached, so a later call retries.
Future<void> ensureInitialized() => _init ??= _loadOnce();

Future<void> _loadOnce() async {
  try {
    await loadBridge();
  } catch (_) {
    _init = null;
    rethrow;
  }
}
