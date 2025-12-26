import 'package:dart_jwk_duo/dart_jwk_duo.dart';

/// Example demonstrating the optional key pair verification functionality.
Future<void> main() async {
  print('Dart JWK Duo - Key Pair Verification Example');
  print('=====================================\n');

  // Generate a key duo
  const KeyDuoGenerator generator = KeyDuoGenerator();
  final KeyDuo keyDuo = await generator.generateKeyDuo();
  
  print('✓ Generated key duo with signing and encryption key pairs');

  // Verify signing key pair
  print('\n1. Verifying signing key pair...');
  final bool signingValid = await keyDuo.signingKeyPair.verifyKeyPair();
  print('   Result: ${signingValid ? "✓ Valid" : "✗ Invalid"}');

  // Verify encryption key pair
  print('\n2. Verifying encryption key pair...');
  final bool encryptionValid = await keyDuo.encryptionKeyPair.verifyKeyPair();
  print('   Result: ${encryptionValid ? "✓ Valid" : "✗ Invalid"}');

  // Verify entire KeyDuo at once
  print('\n3. Verifying entire KeyDuo...');
  final bool duoValid = await keyDuo.verify();
  print('   Result: ${duoValid ? "✓ Valid" : "✗ Invalid"}');

  // Test public-only key pair verification (should throw StateError)
  print('\n4. Testing public-only key pair verification...');
  final SigningKeyPair publicOnlySigningPair = SigningKeyPair.publicOnly(
    publicKey: keyDuo.signing.publicKey,
  );
  
  try {
    await publicOnlySigningPair.verifyKeyPair();
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