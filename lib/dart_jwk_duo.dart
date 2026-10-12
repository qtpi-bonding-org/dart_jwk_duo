/// Type-safe P-256 key pairs (ES256 signing, HPKE encryption), JWK import and
/// export, and AES-256-GCM, over the rust_jwk_duo library via flutter_rust_bridge.
library dart_jwk_duo;

// Constants and configuration
export 'src/constants.dart';

// Encoding — the single hex and public key encoding used throughout
export 'src/hex_codec.dart';
export 'src/sec1_public_key.dart';
export 'src/public_key_hex.dart';

// Core interfaces and DTOs
export 'src/interfaces.dart';
export 'src/exported_jwk.dart' show ExportedJwk;
export 'src/init.dart' show ensureInitialized;

// Key pair implementations
export 'src/signing_key_pair.dart' show SigningKeyPair;
export 'src/encryption_key_pair.dart' show EncryptionKeyPair;

// Key containers
export 'src/key_duo.dart' show KeyDuo;
export 'src/symmetric_key.dart' show SymmetricKey;

// 4 Services - Clean separation of concerns
export 'src/generation_service.dart' show GenerationService;
export 'src/validation_service.dart';
export 'src/verification_service.dart';
export 'src/crypto_service.dart';

// Serialization
export 'src/key_duo_serializer.dart';

// Utilities
export 'src/jwk_thumbprint.dart';