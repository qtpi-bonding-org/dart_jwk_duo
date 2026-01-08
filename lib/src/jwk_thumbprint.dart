/// RFC 7638 JWK thumbprint calculation utilities.
library;

import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';

/// Calculates RFC 7638 JWK thumbprint for a given JWK.
/// 
/// The thumbprint is calculated by:
/// 1. Extracting only the required members for the key type
/// 2. Sorting the members lexicographically by key name
/// 3. Creating a canonical JSON representation
/// 4. Computing SHA-256 hash of the UTF-8 bytes
/// 5. Base64url encoding the hash (without padding)
/// 
/// For EC keys, the required members are: crv, kty, x, y
/// 
/// [jwk] - The JWK as a Map to calculate thumbprint for
/// Returns the base64url-encoded SHA-256 hash of the canonical JWK
/// Throws [ArgumentError] if validation fails or required members are missing/invalid
Future<String> calculateJwkThumbprint(Map<String, dynamic> jwk) async {
  // Extract and validate key type first
  final dynamic ktyValue = jwk['kty'];
  if (ktyValue == null) {
    throw ArgumentError('Missing required JWK member: kty is required');
  }
  if (ktyValue is! String) {
    throw ArgumentError('JWK member "kty" must be a String, got ${ktyValue.runtimeType}');
  }
  if (ktyValue != 'EC') {
    throw ArgumentError('Only EC keys are supported for thumbprint calculation');
  }
  
  // Extract required EC components
  final dynamic crvValue = jwk['crv'];
  final dynamic xValue = jwk['x'];
  final dynamic yValue = jwk['y'];
  
  // Validate presence
  if (crvValue == null || xValue == null || yValue == null) {
    throw ArgumentError('Missing required JWK member: crv, x, and y are required for EC keys');
  }
  
  // Validate types
  if (crvValue is! String || xValue is! String || yValue is! String) {
    throw ArgumentError('JWK members crv, x, and y must be strings');
  }
  
  // Create RFC 7638 canonical JSON: {"crv":"P-256","kty":"EC","x":"...","y":"..."}
  // Note: SplayTreeMap automatically sorts keys lexicographically
  final SplayTreeMap<String, String> canonicalJwk = SplayTreeMap<String, String>.from({
    'crv': crvValue,
    'kty': ktyValue,
    'x': xValue,
    'y': yValue,
  });
  
  final String canonicalJson = jsonEncode(canonicalJwk);
  
  // Compute SHA-256 hash
  final Uint8List utf8Bytes = utf8.encode(canonicalJson);
  final Uint8List hashBytes = await Hash.sha256.digestBytes(utf8Bytes);
  
  // Base64url encode without padding
  return base64Url.encode(hashBytes).replaceAll('=', '');
}