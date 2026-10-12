/// Service for generating new cryptographic keys.
library;

import 'bridge/api.dart' as r;
import 'encryption_key_pair.dart';
import 'errors.dart';
import 'init.dart';
import 'key_duo.dart';
import 'signing_key_pair.dart';
import 'symmetric_key.dart';

/// Service for generating new cryptographic keys.
class GenerationService {
  /// Generate new KeyDuo (ECDSA P-256 signing + HPKE P-256 encryption).
  static Future<KeyDuo> generateKeyDuo() async {
    await ensureInitialized();
    return keyDuoFromParts(rethrowAsDart(r.generateKeyDuo));
  }

  /// Generate new symmetric key (AES-256-GCM).
  static Future<SymmetricKey> generateSymmetricKey() async {
    await ensureInitialized();
    return symmetricKeyFromHandle(rethrowAsDart(r.symmetricGenerate));
  }
}

/// Internal: wraps a bridge key duo (the barrel exports only [GenerationService]).
KeyDuo keyDuoFromParts(r.RDuoParts parts) => KeyDuo(
      signing: signingKeyPairFromHandle(parts.signing),
      encryption: encryptionKeyPairFromHandle(parts.encryption),
    );
