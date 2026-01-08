import 'package:dart_jwk_duo/dart_jwk_duo.dart';

/// Example demonstrating the optional key pair verification functionality.
Future<void> main() async {
  print('Dart JWK Duo - Key Pair Verification Example');
  print('=====================================\n');

  // Generate a key duo using GenerationService
  final KeyDuo keyDuo = await GenerationService.generateKeyDuo();
  
  print('✓ Generated key duo with signing and encryption key pairs');

  // Verify signing key pair using VerificationService
  print('\n1. Verifying signing key pair...');
  final bool signingValid = await VerificationService.verifySigningKeyPair(keyDuo.signingKeyPair);
  print('   Result: ${signingValid ? "✓ Valid" : "✗ Invalid"}');

  // Verify encryption key pair using VerificationService
  print('\n2. Verifying encryption key pair...');
  final bool encryptionValid = await VerificationService.verifyEncryptionKeyPair(keyDuo.encryptionKeyPair);
  print('   Result: ${encryptionValid ? "✓ Valid" : "✗ Invalid"}');

  // Verify entire KeyDuo at once using VerificationService
  print('\n3. Verifying entire KeyDuo...');
  final bool duoValid = await VerificationService.verifyKeyDuo(keyDuo);
  print('   Result: ${duoValid ? "✓ Valid" : "✗ Invalid"}');

  // Test public-only key pair verification (should throw StateError)
  print('\n4. Testing public-only key pair verification...');
  final SigningKeyPair publicOnlySigningPair = SigningKeyPair.publicOnly(
    publicKey: keyDuo.signing.publicKey,
  );
  
  try {
    await VerificationService.verifySigningKeyPair(publicOnlySigningPair);
    print('   Result: ✗ Unexpected success');
  } catch (e) {
    if (e is StateError) {
      print('   Result: ✓ Correctly threw StateError for public-only key pair');
    } else {
      print('   Result: ✗ Unexpected error: $e');
    }
  }

  print('\n✓ All verification tests completed successfully!');
  print('\nNote: Key pair verification is optional and should only be used');
  print('when key pair integrity is uncertain, as it involves expensive');
  print('cryptographic operations.');
}