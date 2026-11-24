/// Builds the wasm and JS files a web app needs:
///   dart run dart_jwk_duo:build_web [--output web/pkg] [--install-wasm-bindgen]
library;

import 'dart:io';
import 'dart:isolate';

const String _stem = 'dart_jwk_duo_bridge';
const String _target = 'wasm32-unknown-unknown';
const String _usage = '''
Usage: dart run dart_jwk_duo:build_web [options]

Run from the app's root. Needs cargo and the $_target Rust target.

  --output <dir>            Where to put the files (default: web/pkg)
  --install-wasm-bindgen    Install the matching wasm-bindgen CLI under
                            .dart_tool/dart_jwk_duo (not globally) if missing

Environment: WASM_BINDGEN = path to a wasm-bindgen binary (default: from PATH).
''';

Future<void> main(List<String> args) async {
  try {
    await _run(args);
  } on _Failure catch (e) {
    stderr.writeln('build_web: ${e.message}');
    exitCode = 1;
  }
}

class _Failure implements Exception {
  _Failure(this.message);
  final String message;
}

Future<void> _run(List<String> args) async {
  String output = 'web/pkg';
  bool install = false;
  for (int i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--output' when i + 1 < args.length:
        output = args[++i];
      case '--install-wasm-bindgen':
        install = true;
      case '--help' || '-h':
        stdout.write(_usage);
        return;
      default:
        throw _Failure('unknown argument ${args[i]}\n$_usage');
    }
  }

  final Uri? lib = await Isolate.resolvePackageUri(Uri.parse('package:dart_jwk_duo/'));
  if (lib == null) throw _Failure('cannot locate package:dart_jwk_duo');
  final String crate = lib.resolve('../rust/').toFilePath();
  // Build in the app, not in the (possibly shared, read-only) package checkout.
  final String work = Directory.current.uri.resolve('.dart_tool/dart_jwk_duo/').toFilePath();

  // The CLI must equal the locked crate version, so find it before building.
  final String version = _lockedVersion(File('${crate}Cargo.lock').readAsStringSync());
  final String bindgen = await _wasmBindgen(version, work, install);

  await _exec('cargo', <String>[
    'build', '--release', '--locked', '--target', _target,
    '--manifest-path', '${crate}Cargo.toml', '--target-dir', '${work}target', //
  ], hint: 'If the target is missing: rustup target add $_target');

  final Directory out = Directory(output)..createSync(recursive: true);
  await _exec(bindgen, <String>[
    '--target', 'no-modules', '--no-typescript', '--out-dir', out.path,
    '${work}target/$_target/release/$_stem.wasm', //
  ]);

  // Keep wasm-bindgen's top-level `let` out of the page's global scope and
  // publish the module under our own name, which lib/src/init_web.dart reads.
  final File js = File('${out.path}/$_stem.js');
  js.writeAsStringSync('(function () {\n${js.readAsStringSync()}\n'
      'globalThis.dartJwkDuoBridge = wasm_bindgen;\n})();\n');
  final int size = File('${out.path}/${_stem}_bg.wasm').lengthSync();
  stdout.writeln('build_web: wrote $_stem.js and ${_stem}_bg.wasm ($size bytes) to ${out.path}');
}

String _lockedVersion(String lock) {
  final RegExpMatch? m = RegExp(r'name = "wasm-bindgen"\r?\nversion = "([^"]+)"').firstMatch(lock);
  if (m == null) throw _Failure('wasm-bindgen is not in rust/Cargo.lock');
  return m.group(1)!;
}

Future<String> _wasmBindgen(String version, String work, bool install) async {
  final String root = '${work}wasm-bindgen-$version';
  final String local = '$root/bin/wasm-bindgen${Platform.isWindows ? '.exe' : ''}';
  final String? explicit = Platform.environment['WASM_BINDGEN'];
  final List<String> found = <String>[];
  for (final String exe in <String>[if (explicit != null) explicit else ...<String>[local, 'wasm-bindgen']]) {
    final String? v = await _versionOf(exe);
    if (v == version) return exe;
    if (v != null) found.add('$exe is $v');
  }
  final List<String> cmd = <String>['install', 'wasm-bindgen-cli', '--version', version, '--locked'];
  if (install && explicit == null) {
    await _exec('cargo', <String>[...cmd, '--root', root]);
    return local;
  }
  throw _Failure('needs wasm-bindgen CLI $version (${found.isEmpty ? 'none found' : found.join(', ')}).\n'
      'Pass --install-wasm-bindgen, or run: cargo ${cmd.join(' ')}');
}

Future<String?> _versionOf(String exe) async {
  try {
    final ProcessResult r = await Process.run(exe, <String>['--version']);
    return r.exitCode == 0 ? (r.stdout as String).trim().split(' ').last : null;
  } on ProcessException {
    return null;
  }
}

Future<void> _exec(String exe, List<String> args, {String? hint}) async {
  final int code;
  try {
    final Process p = await Process.start(exe, args, mode: ProcessStartMode.inheritStdio);
    code = await p.exitCode;
  } on ProcessException catch (e) {
    throw _Failure('cannot run $exe: ${e.message}');
  }
  if (code != 0) throw _Failure('$exe failed with exit code $code.${hint == null ? '' : '\n$hint'}');
}
