/// A thin, type-safe wrapper around package:webcrypto for managing
/// cryptographic key pairs with clean service-based architecture.
library dart_jwk_duo;

// Constants and configuration
export 'src/constants.dart';
export 'src/key_id_formatting.dart';

// Core interfaces and DTOs
export 'src/interfaces.dart';
export 'src/exported_jwk.dart';

// Key pair implementations
export 'src/signing_key_pair.dart';
export 'src/encryption_key_pair.dart';

// Key containers
export 'src/key_duo.dart';
export 'src/symmetric_key.dart';

// 4 Services - Clean separation of concerns
export 'src/generation_service.dart';
export 'src/validation_service.dart';
export 'src/verification_service.dart';
export 'src/crypto_service.dart';

// Serialization
export 'src/key_duo_serializer.dart';

// Utilities
export 'src/jwk_thumbprint.dart';