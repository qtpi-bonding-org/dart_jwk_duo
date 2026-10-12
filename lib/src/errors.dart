import 'dart:convert';
import 'bridge/api.dart' as r;

/// Every bridge call goes through here, so callers only ever see 2.x's
/// exception types.
T rethrowAsDart<T>(T Function() call) {
  try {
    return call();
  } on r.RError catch (e) {
    switch (e.kind) {
      case r.RErrorKind.format:
        throw FormatException(e.message);
      case r.RErrorKind.state:
        throw StateError(e.message);
      case r.RErrorKind.argument:
        throw ArgumentError(e.message);
    }
  }
}

/// JSON-encodes a `Map` argument for the bridge. A value that is not valid
/// JSON surfaces as [FormatException], never a raw `JsonUnsupportedObjectError`.
String encodeJsonArg(Object? value) {
  try {
    return jsonEncode(value);
  } on JsonUnsupportedObjectError {
    throw const FormatException('Invalid JSON format');
  }
}
