/// RFC 7638 JWK thumbprint calculation utilities.
library;

import 'bridge/api.dart' as r;
import 'errors.dart';
import 'init.dart';

/// Calculates the RFC 7638 JWK thumbprint for a given EC JWK.
///
/// The thumbprint is the base64url (no padding) SHA-256 of the canonical JSON
/// of the required members `crv`, `kty`, `x`, `y`, computed by rust_jwk_duo.
///
/// Throws [ArgumentError] if required members are missing or invalid.
Future<String> calculateJwkThumbprint(Map<String, dynamic> jwk) async {
  await ensureInitialized();
  return rethrowAsDart(() => r.jwkThumbprint(jwkJson: encodeJsonArg(jwk)));
}
