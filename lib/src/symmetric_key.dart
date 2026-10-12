/// Type-safe wrapper for AES-256-GCM symmetric keys.
library;

import 'bridge/api.dart' as r;
import 'errors.dart';
import 'init.dart';

/// Type-safe wrapper for AES-256-GCM symmetric keys.
///
/// Wraps a native handle; the key bytes stay in Rust until [toJwk] is called.
class SymmetricKey {
  SymmetricKey._(this._r);
  final r.RSymmetricKey _r;

  /// Import from JWK string.
  ///
  /// Use `ValidationService.validateSymmetricKeyJwkString()` first if
  /// separate validation is needed.
  ///
  /// Throws [FormatException] if import fails.
  static Future<SymmetricKey> fromJwk(String jwk) async {
    await ensureInitialized();
    return SymmetricKey._(rethrowAsDart(() => r.symmetricFromJwk(json: jwk)));
  }

  /// Export as JWK format JSON string.
  Future<String> toJwk() async {
    await ensureInitialized();
    return rethrowAsDart(() => r.symmetricToJwk(k: _r));
  }

  /// Releases the native key handle. The key must not be used afterwards.
  void dispose() => _r.dispose();

  /// The native handle, for the facade's own services.
  r.RSymmetricKey get handle => _r;
}

/// Wraps a native symmetric handle. Internal: not exported from the barrel.
SymmetricKey symmetricKeyFromHandle(r.RSymmetricKey h) => SymmetricKey._(h);
