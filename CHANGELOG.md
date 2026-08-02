# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-08-01

Breaking release. The library now speaks exactly one public key encoding,
symmetrically across both key pair types.

### Changed — BREAKING

- **Public keys are SEC1 uncompressed only** (`04 || x || y`, 65 bytes /
  130 hex). The bare 128-hex coordinate form is gone entirely; it is now
  rejected on import rather than silently accepted.
  - `SigningKeyPair.exportPublicKeyHex()` → `exportPublicKeySec1Hex()` (130, not 128)
  - `SigningKeyPair.importPublicKeyHex()` → `importPublicKeySec1Hex()` (130, not 128)
  - `VerificationService.verifySignatureWithPublicKeyHex()` →
    `verifySignatureWithPublicKeySec1Hex()`, parameter renamed to `publicKeySec1Hex`
  - `KeyDuoSerializer.extractSigningPublicKeyHex()` →
    `extractSigningPublicKeySec1Hex()`
- **`CryptoService` takes the specific key pair, not a whole `KeyDuo`.**
  `encrypt`/`decrypt`/`encryptString`/`decryptString` now take an
  `EncryptionKeyPair`; `sign`/`verifySignature`/`signString`/
  `verifySignatureString` now take a `SigningKeyPair`. This is what makes
  encrypting to a public-only recipient possible.
- **Malformed encoding throws `FormatException`, never `ArgumentError`.**
  Length, non-hex characters, a wrong tag byte and an off-curve point now all
  raise the same type — matching what `webcrypto` already threw for bad points.
- `ValidationService.parseValidatedHex()` removed; use `HexCodec.decode()`.
- Constants `ecP256RawPublicKeyLength`, `ecP256CoordinatesLength` and
  `ecP256PublicKeyHexLength` replaced by `ecP256Sec1PublicKeyLength` (65),
  `ecP256Sec1PublicKeyHexLength` (130) and `sec1UncompressedTag` (0x04).

- **Public key hex is typed, not a bare `String`.** `exportPublicKeySec1Hex()`
  now returns [SigningPublicKeyHex] or [EncryptionPublicKeyHex] depending on
  the key pair, and the matching `importPublicKeySec1Hex()` takes that type.
  Passing a signing key where an encryption key belongs is a compile error.
  These are extension types, so they cost nothing at runtime. A value read
  from storage must be wrapped explicitly: `SigningPublicKeyHex(hexFromDb)`.
- **The hybrid encryption wire format is fixed-layout.** Was a 4-byte length
  prefix followed by the ephemeral public key as a JSON JWK; is now a plain
  65-byte SEC1 point. Ciphertexts produced by 1.x cannot be decrypted.

  ```
  | ephemeral SEC1 public key | HKDF salt | AES-GCM IV | ciphertext + tag |
  |         65 bytes          | 32 bytes  |  12 bytes  |     variable     |
  ```

  This deletes the length prefix, the JSON encode/decode, the manual
  `kty`/`crv` check and the `maxEphemeralKeyLength` DoS guard — with every
  field at a constant offset there is no attacker-controlled length left to
  bound. Constants `lengthPrefixSize` and `maxEphemeralKeyLength` are gone;
  `hybridHeaderLength` and `aesGcmTagLength` replace them.
- `CryptoService.decryptSymmetric` now throws `FormatException` rather than
  `ArgumentError` on a too-short input, and checks for the GCM tag as well as
  the IV.

### Added

- `SigningPublicKeyHex`, `EncryptionPublicKeyHex` and `PublicKeyDuo` — see
  above. `PublicKeyDuo` has typed slots, so its two keys cannot be
  transposed, and it refuses construction if both slots hold the same key.
  Over the wire it uses the field names `signingPublicKeyHex` and
  `encryptionPublicKeyHex`.
- `KeyDuo.exportPublicKeyDuo()` and `KeyDuoSerializer.extractPublicKeyDuo()`.
- `EncryptionKeyPair` gains the full encoding surface it was missing:
  `exportPublicKeySec1Hex()`, `exportPublicKeyRaw()`,
  `importPublicKeySec1Hex()`, `importPublicKeyRaw()`.
- `exportPublicKeySec1Hex()` and `exportPublicKeyRaw()` are declared on
  `IKeyPair`, so the two pair types can no longer drift apart — a missing
  member is a compile error, not a discovery months later.
- `importPublicKeyRaw()` on both pair types, for callers already holding bytes.
- `KeyDuoSerializer.extractEncryptionPublicKeySec1Hex()`, mirroring the
  signing extractor.
- `HexCodec` — the single definition of hex used library-wide, replacing three
  copies of an inline `toRadixString(16).padLeft(2, '0')` loop.
- `Sec1PublicKey` — the single definition of the SEC1 point encoding, replacing
  the ad-hoc `04`-prefix surgery that used to live inside
  `SigningKeyPair.importPublicKeyHex`.
- Tests pinning: SEC1 round trips for both pair types, exact length and tag,
  rejection of wrong length / non-hex / wrong tag / off-curve points, key
  distinctness, encrypt-to-public-key, and that signing and encryption public
  keys are byte-indistinguishable.

### Removed

- Dead `try { ... } catch (e) { rethrow; }` blocks in `GenerationService`.
- The temporary throwaway `KeyDuo` that `VerificationService`
  `verifyEncryptionKeyPair` used to construct just to reach `CryptoService`.

## [1.0.0] - 2024-12-14

### Added
- Initial project structure and dependencies
- Type-safe wrapper interfaces for RSA key pairs
- JWK Set export/import functionality
- RFC 7517 compliant JWK format support
- RFC 7638 JWK thumbprint calculation for dynamic key IDs
- Configurable key identifiers with sensible defaults