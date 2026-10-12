/// Type-safe wrapper for ECDSA P-256 signing key pairs.
library;

import 'dart:typed_data';
import 'bridge/api.dart' as r;
import 'errors.dart';
import 'exported_jwk.dart';
import 'init.dart';
import 'interfaces.dart';
import 'public_key_hex.dart';
import 'sec1_public_key.dart';

/// Type-safe wrapper for ECDSA P-256 signing key pairs (ES256).
///
/// Wraps a native handle; the private scalar never enters Dart.
class SigningKeyPair implements IKeyPair {
  SigningKeyPair._(this._r, this._publicRaw);
  final r.RSigningKeyPair _r;
  final Uint8List _publicRaw; // cached for synchronous distinctness checks

  /// Import a public-only SigningKeyPair from SEC1 uncompressed hex.
  ///
  /// Takes a [SigningPublicKeyHex] rather than a bare `String` so that an
  /// encryption key cannot be imported here by accident — the two are
  /// byte-indistinguishable, so the type is the only thing that can tell them
  /// apart.
  ///
  /// Throws [FormatException] if the bytes do not describe a point on P-256.
  static Future<SigningKeyPair> importPublicKeySec1Hex(SigningPublicKeyHex sec1Hex) =>
      importPublicKeyRaw(Sec1PublicKey.decodeHex(sec1Hex.value));

  /// Import a public-only SigningKeyPair from SEC1 uncompressed bytes.
  ///
  /// Throws [FormatException] if the length or tag is wrong, or if the bytes
  /// do not describe a point on P-256.
  static Future<SigningKeyPair> importPublicKeyRaw(Uint8List raw) async {
    await ensureInitialized();
    return signingKeyPairFromHandle(
        rethrowAsDart(() => r.signingImportPublicRaw(raw: Sec1PublicKey.validateRaw(raw))));
  }

  /// The SEC1 public key bytes, cached at creation.
  Uint8List get cachedPublicRaw => _publicRaw;

  @override
  bool get hasPrivateKey => r.signingHasPrivateKey(kp: _r);

  /// Sign bytes with the private key. Returns a 64-byte P1363 `r || s`.
  ///
  /// Throws [StateError] on a public-only key pair.
  Future<Uint8List> signBytes(Uint8List data) async {
    await ensureInitialized();
    return Uint8List.fromList(rethrowAsDart(() => r.signBytes(kp: _r, data: data)));
  }

  /// Verify a signature against the original data. Returns `false` for a
  /// malformed signature.
  Future<bool> verifyBytes(Uint8List signature, Uint8List data) async {
    await ensureInitialized();
    return rethrowAsDart(() => r.verifyBytes(kp: _r, signature: signature, data: data));
  }

  @override
  Future<Uint8List> exportPublicKeyRaw() async => Uint8List.fromList(_publicRaw);

  /// Export the public key as SEC1 uncompressed hex, typed as a signing key.
  @override
  Future<SigningPublicKeyHex> exportPublicKeySec1Hex() async =>
      SigningPublicKeyHex(Sec1PublicKey.encodeHex(_publicRaw));

  @override
  Future<ExportedJwk> exportPrivateKey() async {
    await ensureInitialized();
    return exportedJwkFromJson(rethrowAsDart(() => r.signingExportPrivateJwk(kp: _r)));
  }

  @override
  Future<ExportedJwk> exportPublicKey() async {
    await ensureInitialized();
    return exportedJwkFromJson(rethrowAsDart(() => r.signingExportPublicJwk(kp: _r)));
  }

  @override
  Future<String> calculateKeyId() async {
    await ensureInitialized();
    return rethrowAsDart(() => r.signingKeyId(kp: _r));
  }

  @override
  void dispose() => _r.dispose();

  /// The native handle, for the facade's own services.
  r.RSigningKeyPair get handle => _r;
}

/// Wraps a native signing handle. Internal: not exported from the barrel.
SigningKeyPair signingKeyPairFromHandle(r.RSigningKeyPair h) =>
    SigningKeyPair._(h, Uint8List.fromList(r.signingPublicRaw(kp: h)));
