import 'package:jwk_duo/jwk_duo.dart';

/// Example demonstrating the optional key pair validation functionality.
Future<void> main() async {
  print('JWK Duo - Key Pair Validation Example');
  print('=====================================\n');

  // Generate a key duo
  final generator = KeyDuoGenerator();
  final keyDuo = await generator.generateKeyDuo();
  
  print('✓ Generated key duo with signing and encryption key pairs');

  // Validate signing key pair
  print('\n1. Validating signing key pair...');
  final signingValid = await keyDuo.signing.validateKeyPair();
  print('   Result: ${signingValid ? "✓ Valid" : "✗ Invalid"}');

  // Validate encryption key pair
  print('\n2. Validating encryption key pair...');
  final encryptionValid = await keyDuo.encryption.validateKeyPair();
  print('   Result: ${encryptionValid ? "✓ Valid" : "✗ Invalid"}');

  // Test public-only key pair validation (should throw StateError)
  print('\n3. Testing public-only key pair validation...');
  final publicOnlySigningPair = SigningKeyPair.publicOnly(
    publicKey: keyDuo.signing.publicKey,
  );
  
  try {
    await publicOnlySigningPair.validateKeyPair();
    print('   Result: ✗ Unexpected success');
  } catch (e) {
    if (e is StateError) {
      print('   Result: ✓ Correctly threw StateError for public-only key pair');
    } else {
      print('   Result: ✗ Unexpected error: $e');
    }
  }

  print('\n✓ All validation tests completed successfully!');
  print('\nNote: Key pair validation is optional and should only be used');
  print('when key pair integrity is uncertain, as it involves expensive');
  print('cryptographic operations.');
}