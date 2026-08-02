# Brief: give `EncryptionKeyPair` the same hex surface as `SigningKeyPair`

**Date:** 2026-08-01
**Requested by:** `serverpod_anonaccred` (see its
`docs/superpowers/specs/2026-08-01-account-device-principal-parity-design.md`)
**Status:** proposal — naming and deprecation are this repo's call

---

## Why

`serverpod_anonaccred` is standardising every P-256 public key it stores or
transmits on **one** encoding: SEC1 uncompressed, `04||x||y`, 130 hex chars. It
currently has three different conventions in flight for the same kind of value,
which produced a live bug (a signing key stored in a field meant for an
encryption key, undetected for months).

Tracing that back lands here. This library's two key pairs have asymmetric APIs:

| | `SigningKeyPair` | `EncryptionKeyPair` |
|---|---|---|
| `exportPublicKeyHex()` (128, bare `x‖y`) | ✅ `signing_key_pair.dart:90` | ❌ |
| `exportPublicKeyRaw()` (65 bytes, `04`-prefixed) | ✅ `:85` | ❌ |
| `importPublicKeyHex()` | ✅ `:43` | ❌ |
| `exportPublicKey()` (JWK) | ✅ `:123` | ✅ `encryption_key_pair.dart:71` |
| `exportPrivateKey()` (JWK) | ✅ | ✅ |
| `calculateKeyId()` | ✅ | ✅ |

Downstream code sends **hex for signing keys and JWK for encryption keys** — not
by choice, but because for ECDH keys hex was never offered. Closing this gap
lets consumers use one encoding for both, which is the actual fix.

## What's asked for

**1. Mirror the signing surface on `EncryptionKeyPair`.** Same three members,
same semantics, so the two pair types are interchangeable at the encoding
boundary.

**2. Add explicit SEC1-uncompressed hex accessors on both pair types.** The
existing `exportPublicKeyHex()` returns the *bare* 128-hex form — SEC1 with its
tag stripped. That form is this library's convenience, not a named standard, and
it means callers who need the standard form must do prefix surgery themselves
(`signing_key_pair.dart:47-50` already does exactly that internally on import).

Suggested, but name them however fits this repo's conventions:

```dart
Future<String> exportPublicKeySec1Hex();          // 130 hex, 04||x||y
static Future<T> importPublicKeySec1Hex(String);  // accepts 130 hex
```

**3. Decide what happens to the existing bare-128 accessors.** Options: keep them
alongside with a doc comment stating the encoding explicitly; or deprecate them
in favour of the SEC1 form. Not our call — this library may have consumers we
can't see. What matters downstream is that a SEC1 path exists and that each
accessor's doc comment states its exact encoding and byte length. Please do
**not** silently change what `exportPublicKeyHex()` returns; a same-name
behaviour change is the worst outcome for existing callers.

## Why SEC1 uncompressed rather than the bare form

Not a preference — it's what everything else already speaks. SEC1 §2.3.3, and
identically ANSI X9.62, RFC 5480, TLS, OpenSSL/BoringSSL, and WebCrypto's `"raw"`
format. `webcrypto`'s `importRawKey`/`exportRawKey` require it, which is why
`SigningKeyPair.importPublicKeyHex` has to prepend `0x04` before delegating.
Standardising on it removes prefix surgery on both sides of the boundary rather
than moving it around.

## Tests we'd want to rely on

Stated as behaviours, not as a prescribed file layout:

- **Round trip, both pair types.** `export → import → export` is byte-identical,
  for the SEC1 form and for whatever bare form survives.
- **Length and prefix are exact.** SEC1 export is exactly 130 hex chars and
  begins `04`; bare export is exactly 128 and does not.
- **Cross-encoding equivalence.** The SEC1 and bare exports of the same key
  denote the same point — i.e. `sec1 == '04' + bare`. Consumers rely on this to
  compare keys across encodings without a full decode.
- **Distinctness.** Two independently generated key pairs never produce equal
  public key hex, in either encoding. And within one `KeyDuo`, the signing and
  encryption public keys are never equal — downstream will assert this as an
  invariant, so it should hold here first.
- **Invalid input is rejected, not silently mangled.** Import must throw on:
  wrong length; non-hex characters; a 130-hex string whose first byte isn't `04`;
  and a well-formed-but-off-curve point. That last one matters most — a point not
  on P-256 must not import successfully. If `webcrypto`/BoringSSL already rejects
  it, a test pinning that behaviour is enough; we'd rather depend on a tested
  guarantee than an assumed one.
- **Signing and encryption keys are byte-indistinguishable.** Worth an explicit
  test asserting that a signing public key and an encryption public key of the
  same length are not tellable apart by inspection. It's the reason downstream
  has to carry purpose in field names and types, and pinning it stops anyone
  later "optimising" by trying to sniff the key type.

## What downstream will do with it

Every public key field becomes SEC1 130-hex, with purpose carried by the field
name (`...SigningPublicKeyHex` / `...EncryptionPublicKeyHex`) and by a typed
`PublicKeyDuo` wire model rather than by encoding. Since the two key types are
indistinguishable by their bytes, naming and typing are the only mechanisms
available — hence the request to make both encodings available symmetrically, so
the choice is semantic rather than forced by API availability.
