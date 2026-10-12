/// Type-safe wrapper for P-256 HPKE encryption key pairs.
library;

import 'dart:typed_data';
import 'bridge/api.dart' as r;
import 'errors.dart';
import 'exported_jwk.dart';
import 'init.dart';
import 'interfaces.dart';
import 'public_key_hex.dart';
import 'sec1_public_key.dart';

/// Type-safe wrapper for P-256 HPKE encryption key pairs (alg HPKE-7).
///
/// Wraps a native handle; the private scalar never enters Dart.
class EncryptionKeyPair implements IKeyPair {
  EncryptionKeyPair._(this._r, this._publicRaw);
  final r.REncryptionKeyPair _r;
  final Uint8List _publicRaw; // cached for synchronous distinctness checks

  /// Import a public-only EncryptionKeyPair from SEC1 uncompressed hex.
  ///
  /// Takes a [EncryptionPublicKeyHex] rather than a bare `String` so that a
  /// signing key cannot be imported here by accident — the two are
  /// byte-indistinguishable, so the type is the only thing that can tell them
  /// apart.
  ///
  /// Throws [FormatException] if the bytes do not describe a point on P-256.
  static Future<EncryptionKeyPair> importPublicKeySec1Hex(EncryptionPublicKeyHex sec1Hex) =>
      importPublicKeyRaw(Sec1PublicKey.decodeHex(sec1Hex.value));

  /// Import a public-only EncryptionKeyPair from SEC1 uncompressed bytes.
  ///
  /// Throws [FormatException] if the length or tag is wrong, or if the bytes
  /// do not describe a point on P-256.
  static Future<EncryptionKeyPair> importPublicKeyRaw(Uint8List raw) async {
    await ensureInitialized();
    return encryptionKeyPairFromHandle(
        rethrowAsDart(() => r.encryptionImportPublicRaw(raw: Sec1PublicKey.validateRaw(raw))));
  }

  @override
  bool get hasPrivateKey => rethrowAsDart(() => r.encryptionHasPrivateKey(kp: _r));

  @override
  Future<Uint8List> exportPublicKeyRaw() async => Uint8List.fromList(_publicRaw);

  /// Export the public key as SEC1 uncompressed hex, typed as an encryption key.
  @override
  Future<EncryptionPublicKeyHex> exportPublicKeySec1Hex() async =>
      EncryptionPublicKeyHex(Sec1PublicKey.encodeHex(_publicRaw));

  @override
  Future<ExportedJwk> exportPrivateKey() async {
    await ensureInitialized();
    return exportedJwkFromJson(rethrowAsDart(() => r.encryptionExportPrivateJwk(kp: _r)));
  }

  @override
  Future<ExportedJwk> exportPublicKey() async {
    await ensureInitialized();
    return exportedJwkFromJson(rethrowAsDart(() => r.encryptionExportPublicJwk(kp: _r)));
  }

  @override
  Future<String> calculateKeyId() async {
    await ensureInitialized();
    return rethrowAsDart(() => r.encryptionKeyId(kp: _r));
  }

  @override
  void dispose() => _r.dispose();
}

/// Internal (the barrel exports only [EncryptionKeyPair]): the native handle.
r.REncryptionKeyPair encryptionHandleOf(EncryptionKeyPair k) => k._r;

/// Internal: the cached public key bytes. The returned buffer is shared, never mutate it.
Uint8List encryptionPublicRawOf(EncryptionKeyPair k) => k._publicRaw;

/// Internal: wraps a native encryption handle.
EncryptionKeyPair encryptionKeyPairFromHandle(r.REncryptionKeyPair h) =>
    EncryptionKeyPair._(h, Uint8List.fromList(r.encryptionPublicRaw(kp: h)));
