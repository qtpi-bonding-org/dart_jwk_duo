/// Types that carry a public key's *purpose* alongside its bytes.
library;

import 'sec1_public_key.dart';

/// A SEC1 public key hex string belonging to a **signing** (ECDSA) key.
///
/// A P-256 public key is just a point on a curve. Nothing in its 130 hex
/// characters says whether it is meant for signatures or for key agreement —
/// a signing key and an encryption key are byte-indistinguishable, and each
/// will import happily as the other. The only thing that can keep them apart
/// is the type system, which is what this exists for.
///
/// This is a Dart extension type: it compiles away entirely, so wrapping a
/// key costs nothing at runtime. It `implements String`, so every `String`
/// member still works and it can be passed anywhere a `String` is wanted —
/// but a [SigningPublicKeyHex] can never be passed where an
/// [EncryptionPublicKeyHex] is expected, or vice versa. That assignment is a
/// compile error rather than a bug discovered months later.
///
/// Values are lowercased on construction, so two spellings of the same key
/// always compare equal.
///
/// **What is and is not checked here.** The constructor is synchronous, so it
/// validates the *encoding* — 130 hex characters, `04` tag — but cannot check
/// that the point actually lies on P-256; that requires an async `webcrypto`
/// import. Curve membership is enforced by
/// [SigningKeyPair.importPublicKeySec1Hex], which is where a key stops being
/// a string and starts being a key. Holding a [SigningPublicKeyHex] therefore
/// means "well-formed, and declared to be a signing key", not "verified to be
/// a valid point".
///
/// ```dart
/// // At the storage boundary, state the purpose once, explicitly:
/// final key = SigningPublicKeyHex(row['signing_public_key_hex'] as String);
/// ```
extension type const SigningPublicKeyHex._(String value) implements String {
  /// Wrap a SEC1 uncompressed public key hex string and validate its encoding.
  ///
  /// Throws [FormatException] if [sec1Hex] is not exactly 130 hex characters
  /// beginning with the `04` tag. Does not check curve membership — see the
  /// class documentation.
  factory SigningPublicKeyHex(String sec1Hex) {
    Sec1PublicKey.decodeHex(sec1Hex);
    return SigningPublicKeyHex._(sec1Hex.toLowerCase());
  }
}

/// A SEC1 public key hex string belonging to an **encryption** (ECDH) key.
///
/// The counterpart to [SigningPublicKeyHex]; see that type for why these
/// exist, and for what the constructor does and does not check. The two are
/// deliberately not interchangeable even though their underlying values are
/// the same shape.
///
/// ```dart
/// final key = EncryptionPublicKeyHex(row['encryption_public_key_hex'] as String);
/// ```
extension type const EncryptionPublicKeyHex._(String value) implements String {
  /// Wrap a SEC1 uncompressed public key hex string and validate its encoding.
  ///
  /// Throws [FormatException] if [sec1Hex] is not exactly 130 hex characters
  /// beginning with the `04` tag. Curve membership is checked by
  /// [EncryptionKeyPair.importPublicKeySec1Hex], not here.
  factory EncryptionPublicKeyHex(String sec1Hex) {
    Sec1PublicKey.decodeHex(sec1Hex);
    return EncryptionPublicKeyHex._(sec1Hex.toLowerCase());
  }
}

/// A signing and an encryption public key travelling together.
///
/// Use this instead of passing two bare hex strings side by side. The slots
/// are typed, so the arguments cannot be transposed — the classic version of
/// this bug is a call site that passes the same key twice, or passes them in
/// the wrong order, and neither can be written here.
///
/// Across the wire, where types are gone, purpose is carried by the JSON
/// field names `signingPublicKeyHex` and `encryptionPublicKeyHex`.
class PublicKeyDuo {
  /// JSON field name for the signing public key.
  static const String signingJsonKey = 'signingPublicKeyHex';

  /// JSON field name for the encryption public key.
  static const String encryptionJsonKey = 'encryptionPublicKeyHex';

  /// The signing (ECDSA) public key, SEC1 hex.
  final SigningPublicKeyHex signing;

  /// The encryption (ECDH) public key, SEC1 hex.
  final EncryptionPublicKeyHex encryption;

  /// Creates a public key duo.
  ///
  /// Throws [ArgumentError] if both slots hold the same key. Two identical
  /// values mean one key was copied into the other's field, which is the
  /// precise failure this type exists to prevent — it is worth refusing even
  /// though the values are individually well formed.
  PublicKeyDuo({
    required this.signing,
    required this.encryption,
  }) {
    if (signing.value == encryption.value) {
      throw ArgumentError(
        'Signing and encryption public keys are identical. One key has been '
        'placed in both fields; they must come from different key pairs.',
      );
    }
  }

  /// Reconstructs a duo from its JSON representation.
  ///
  /// Both keys are validated on the way in. Throws [FormatException] if
  /// either field is missing, is not a string, or is not a valid SEC1 P-256
  /// public key, and [ArgumentError] if the two keys are identical.
  factory PublicKeyDuo.fromJson(Map<String, dynamic> json) {
    final Object? signing = json[signingJsonKey];
    final Object? encryption = json[encryptionJsonKey];

    if (signing is! String) {
      throw FormatException('Missing or non-string "$signingJsonKey"');
    }
    if (encryption is! String) {
      throw FormatException('Missing or non-string "$encryptionJsonKey"');
    }

    return PublicKeyDuo(
      signing: SigningPublicKeyHex(signing),
      encryption: EncryptionPublicKeyHex(encryption),
    );
  }

  /// The JSON representation, with purpose stated in the field names.
  Map<String, dynamic> toJson() => <String, dynamic>{
        signingJsonKey: signing.value,
        encryptionJsonKey: encryption.value,
      };

  @override
  bool operator ==(Object other) =>
      other is PublicKeyDuo &&
      other.signing.value == signing.value &&
      other.encryption.value == encryption.value;

  @override
  int get hashCode => Object.hash(signing.value, encryption.value);

  @override
  String toString() =>
      'PublicKeyDuo(signing: ${signing.value}, encryption: ${encryption.value})';
}
