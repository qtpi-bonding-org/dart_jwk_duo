# dart_jwk_duo 2.0.0 — what changed and what you must do

**Date:** 2026-08-01
**Commit:** `d2fdfb2` on `main` (plus a follow-up rename, see §2)
**Audience:** any repo depending on `dart_jwk_duo` — currently
`quanitya_flutter`, and `serverpod_anonaccred` by way of it.
**Status:** landed, 79 tests passing, `dart analyze` clean.

This is a hard breaking release. There is no compatibility path and none is
wanted: the package had no external consumers and the whole point was to stop
carrying two encodings.

---

## Why this happened

`serverpod_anonaccred` found a live bug — a signing key stored in a field
meant for an encryption key, undetected for months. Tracing it back landed
here. This library's two key pairs had asymmetric APIs: `SigningKeyPair`
could export and import hex, `EncryptionKeyPair` could only speak JWK. So
downstream sent **hex for signing keys and JWK for encryption keys** — not by
choice, but because for ECDH keys hex was never offered.

Two encodings for the same kind of value is how a key ends up in the wrong
field. So the fix was not to add a method; it was to make there be exactly
one encoding, offered identically on both types, with purpose carried by the
type system rather than by which API happened to exist.

---

## 1. One public key encoding: SEC1 uncompressed, 130 hex

Every public key is now `04 || x || y` — 65 bytes, **130** hex characters.
That is SEC1 §2.3.3, and identically ANSI X9.62, RFC 5480, TLS, OpenSSL and
WebCrypto's `"raw"` format.

The bare 128-hex coordinate form is **gone**. It is not deprecated; it is
rejected on import.

```dart
// before                                  // after
exportPublicKeyHex()      // 128           exportPublicKeySec1Hex()   // 130
importPublicKeyHex(hex)   // 128           importPublicKeySec1Hex(hex) // 130
```

`EncryptionKeyPair` now has the same four members `SigningKeyPair` has:
`exportPublicKeySec1Hex`, `exportPublicKeyRaw`, `importPublicKeySec1Hex`,
`importPublicKeyRaw`. The two export members are declared on `IKeyPair`, so
the types cannot drift apart again — a missing member is a compile error.

## 2. Public key hex is typed by purpose

This is the part that actually prevents the original bug, and the part you
will feel most.

```dart
final signing    = await keyDuo.signingKeyPair.exportPublicKeySec1Hex();
final encryption = await keyDuo.encryptionKeyPair.exportPublicKeySec1Hex();
// signing    is SigningPublicKeyHex
// encryption is EncryptionPublicKeyHex

await SigningKeyPair.importPublicKeySec1Hex(encryption);  // compile error
```

`SigningPublicKeyHex` and `EncryptionPublicKeyHex` are Dart **extension
types**: they compile away entirely, so there is no runtime cost and no
allocation. Both `implement String`, so all `String` members work and either
can be passed where a plain `String` is wanted — but never where the *other*
key type is wanted.

Coming back from storage or off the wire, wrap explicitly:

```dart
final key = SigningPublicKeyHex(row['signing_public_key_hex'] as String);
```

**Know the limit.** That constructor is synchronous, so it validates the
*encoding* — 130 chars, `04` tag — but cannot check the point is on the
curve; that needs the async `webcrypto` import, which
`importPublicKeySec1Hex` performs. So holding a `SigningPublicKeyHex` means
*well-formed and declared to be a signing key*, not *verified to be a valid
point*. Don't treat the wrapper as proof of a good key.

For both keys together, prefer `PublicKeyDuo` over two loose strings — typed
slots, so the arguments cannot be transposed, and it throws if both slots
hold the same key:

```dart
final duo = await keyDuo.exportPublicKeyDuo();
duo.toJson();
// {"signingPublicKeyHex": "04…", "encryptionPublicKeyHex": "04…"}
```

Across the wire, where types are gone, those field names carry the purpose.
`serverpod_anonaccred` planned its own `PublicKeyDuo` wire model — this is
that shape, and the JSON keys are chosen to match. Serverpod protocol YAML
can't express extension types, so at the Serverpod boundary the fields stay
`String`; wrap them immediately on the way in.

**Note on §2's naming:** `KeyDuoSerializer`'s four JWK methods were renamed to
end in `Jwk` (`exportKeyDuoJwk`, `exportPublicKeyDuoJwk`, `importKeyDuoJwk`,
`importPublicKeyDuoJwk`) so they don't collide with `KeyDuo.exportPublicKeyDuo()`,
which returns a `PublicKeyDuo` rather than JWK Set JSON.

## 3. CryptoService takes the specific key pair

```dart
// before                              // after
CryptoService.encrypt(data, keyDuo)    CryptoService.encrypt(data, encryptionKeyPair)
CryptoService.decrypt(data, keyDuo)    CryptoService.decrypt(data, encryptionKeyPair)
CryptoService.sign(data, keyDuo)       CryptoService.sign(data, signingKeyPair)
CryptoService.verifySignature(…, keyDuo)  …(…, signingKeyPair)
```

Encrypting to a recipient now needs only their **public** key, mirroring how
verifying needs only the signer's public key. Previously it demanded a whole
`KeyDuo`, which is why callers were building throwaway ones.

`KeyDuo.encrypt/decrypt/sign/verifySignature` still work unchanged as
convenience wrappers over your own keys.

## 4. Wire format is fixed-layout (breaks stored ciphertext)

The ephemeral public key was a JSON JWK behind a 4-byte length prefix. It is
now a plain 65-byte SEC1 point:

```
| ephemeral SEC1 public key | HKDF salt | AES-GCM IV | ciphertext + tag |
|         65 bytes          | 32 bytes  |  12 bytes  |     variable     |
```

Deleting the JSON also deleted the length prefix, the manual `kty`/`crv`
check and the `maxEphemeralKeyLength` DoS guard — with every field at a
constant offset there is no attacker-controlled length left to bound.

**Anything encrypted by 1.x cannot be decrypted by 2.0.**

## 5. Errors are all `FormatException` now

Malformed input throws `FormatException` everywhere — wrong length, non-hex
characters, wrong tag byte, off-curve point, short ciphertext. Previously
length and hex errors threw `ArgumentError` while curve errors threw
`FormatException`, so a caller could not catch a single type.

`ArgumentError` is now reserved for genuine caller-logic errors, e.g.
`PublicKeyDuo` receiving the same key in both slots.

## 6. Smaller changes

- `ValidationService.parseValidatedHex()` removed — use `HexCodec.decode()`.
- New `HexCodec` (the one hex definition) and `Sec1PublicKey` (the one point
  encoding), replacing three copies of an inline `toRadixString` loop and the
  ad-hoc `04`-prefix surgery.
- `KeyDuoSerializer.extractEncryptionPublicKeySec1Hex()` added alongside the
  signing extractor; `extractPublicKeyDuo()` returns both.
- Constants: `ecP256RawPublicKeyLength`, `ecP256CoordinatesLength`,
  `ecP256PublicKeyHexLength`, `lengthPrefixSize`, `maxEphemeralKeyLength` are
  gone. `ecP256Sec1PublicKeyLength` (65), `ecP256Sec1PublicKeyHexLength`
  (130), `sec1UncompressedTag` (0x04), `hybridHeaderLength`,
  `aesGcmTagLength` (16) replace them.
- **SDK constraint raised to `>=3.3.0`** (extension types).

---

## Migration checklist

### Code — `quanitya_flutter`

12 call sites, all compile errors so none can be missed:

| File | Change |
|---|---|
| `device_pairing/services/pairing_service.dart` (×2) | `exportPublicKeyHex()` → `exportPublicKeySec1Hex()` |
| `infrastructure/crypto/key_export_service.dart` (×2) | same, plus `extractSigningPublicKeyHex` → `extractSigningPublicKeySec1Hex` |
| `infrastructure/crypto/crypto_key_repository.dart` (×3) | `exportPublicKeyHex()` → `exportPublicKeySec1Hex()` |
| `infrastructure/auth/account_service.dart` (×4) | same, plus `verifySignatureWithPublicKeyHex(publicKeyHex:)` → `verifySignatureWithPublicKeySec1Hex(publicKeySec1Hex:)` |
| `infrastructure/crypto/data_encryption_service.dart` (×3) | `CryptoService.encrypt/decrypt(x, tempKeyDuo)` → `(x, tempKeyDuo.encryptionKeyPair)`; the throwaway `KeyDuo` may now be unnecessary |

Return types are now the typed wrappers. Where a value goes into a Serverpod
call or a DB write, use `.value` to get the `String`; where one comes back,
wrap it with `SigningPublicKeyHex(...)` / `EncryptionPublicKeyHex(...)`.

### Data — this is the part that needs a plan

Two independent migrations, neither of which the compiler will catch:

1. **Stored public key hex is 128 chars and must become 130.** Prepending
   `"04"` is sufficient and exactly correct — the bare form was the SEC1 form
   with its tag stripped, nothing else changed. Applies to every column,
   cached value and previously-issued token holding a public key hex. Any
   value used as an account identifier changes, so anything keyed on it must
   migrate in the same step.
2. **Ciphertext written by 1.x is unreadable.** There is no in-place
   conversion; the ephemeral key encoding changed. Data must be re-encrypted
   from plaintext, or discarded and regenerated.

Do not deploy the two repos independently — a 130-hex client against a
128-hex server will fail every lookup.

### Field naming, going forward

Since a signing key and an encryption key are byte-indistinguishable and each
imports happily as the other, names are load-bearing wherever types are not.
Use `...SigningPublicKeyHex` / `...EncryptionPublicKeyHex` on every column,
field and parameter. There is a test in this repo pinning the
indistinguishability, specifically so nobody later tries to sniff key type
from the value.

---

## What is now guaranteed, and by what

| Guarantee | Enforced by |
|---|---|
| Both pair types offer the same encoding surface | `IKeyPair` — compile error if not |
| Static import parity | test (statics can't sit on an interface) |
| Signing hex ≠ encryption hex at a call site | extension types — compile error |
| A duo's two keys can't be transposed or duplicated | `PublicKeyDuo` typed slots + constructor check |
| Only 130-hex, `04`-tagged input is accepted | `Sec1PublicKey`, single definition |
| Off-curve points never import | BoringSSL `EC_POINT_oct2point`, pinned by test |
| One hex definition library-wide | `HexCodec`, single definition |
| Encrypted blob overhead is constant | test (rules out variable-length encoding) |

Verified: `dart analyze` reports 0 errors and 0 warnings; 79 tests pass,
run repeatedly to check for flakiness.
