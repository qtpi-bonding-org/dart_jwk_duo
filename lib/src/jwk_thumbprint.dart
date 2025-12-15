/// RFC 7638 JWK thumbprint calculation utilities.
library;

import 'dart:collection';
import 'dart:convert';
import 'package:webcrypto/webcrypto.dart';

/// Calculates RFC 7638 JWK thumbprint for a given JWK.
/// 
/// The thumbprint is calculated by:
/// 1. Extracting only the required members for the key type
/// 2. Validating that n and e are Base64Url-encoded strings (per JWK spec)
/// 3. Sorting the members lexicographically by key name
/// 4. Creating a canonical JSON representation
/// 5. Computing SHA-256 hash of the UTF-8 bytes
/// 6. Base64url encoding the hash (without padding)
/// 
/// For RSA keys, the required members are: kty, n, e
/// All values must be strings, with n and e being valid Base64Url format.
/// 
/// [jwk] - The JWK as a Map to calculate thumbprint for
/// Returns the base64url-encoded SHA-256 hash of the canonical JWK
/// Throws [ArgumentError] if validation fails or required members are missing/invalid
Future<String> calculateJwkThumbprint(Map<String, dynamic> jwk) async {
  // Extract and validate key type first
  final ktyValue = jwk['kty'];
  if (ktyValue == null) {
    throw ArgumentError('Missing required JWK member: kty is required');
  }
  if (ktyValue is! String) {
    throw ArgumentError('JWK member "kty" must be a String, got ${ktyValue.runtimeType}');
  }
  if (ktyValue != 'RSA') {
    throw ArgumentError('Only RSA keys are supported for thumbprint calculation');
  }
  
  // Validate and extract required RSA components with strict type checking
  final nValue = jwk['n'];
  final eValue = jwk['e'];
  
  // Validate presence
  if (nValue == null || eValue == null) {
    throw ArgumentError('Missing required JWK member: n and e are required for RSA keys');
  }
  
  // Validate types - JWK spec requires n and e to be Base64Url-encoded strings
  if (nValue is! String) {
    throw ArgumentError('JWK member "n" must be a Base64Url-encoded String, got ${nValue.runtimeType}');
  }
  if (eValue is! String) {
    throw ArgumentError('JWK member "e" must be a Base64Url-encoded String, got ${eValue.runtimeType}');
  }
  
  // Validate Base64Url format (basic check for valid characters)
  final base64UrlPattern = RegExp(r'^[A-Za-z0-9_-]+$');
  if (!base64UrlPattern.hasMatch(nValue)) {
    throw ArgumentError('JWK member "n" must be valid Base64Url format');
  }
  if (!base64UrlPattern.hasMatch(eValue)) {
    throw ArgumentError('JWK member "e" must be valid Base64Url format');
  }
  
  // Create required members map with validated values
  final requiredMembers = <String, String>{
    'kty': ktyValue,
    'n': nValue,
    'e': eValue,
  };
  
  // Create RFC 7638 compliant canonical JSON using SplayTreeMap for safety
  // SplayTreeMap maintains lexicographic ordering and handles edge cases
  final canonicalJwk = SplayTreeMap<String, String>.from(requiredMembers);
  final String canonicalJson = jsonEncode(canonicalJwk);
  
  // Note: SplayTreeMap approach ensures RFC 7638 compliance by:
  // 1. Automatic lexicographic ordering of member names
  // 2. Proper JSON escaping handled by jsonEncode
  // 3. Consistent output regardless of input order
  // 4. Safe handling of edge cases in Base64 values
  
  // Compute SHA-256 hash
  final utf8Bytes = utf8.encode(canonicalJson);
  final hashBytes = await Hash.sha256.digestBytes(utf8Bytes);
  
  // Base64url encode without padding
  return base64Url.encode(hashBytes).replaceAll('=', '');
}