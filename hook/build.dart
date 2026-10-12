import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

const String _libraryStem = 'dart_jwk_duo_bridge';
const String _assetName = 'src/bridge/frb_generated.dart';

void main(List<String> args) async {
  await build(args, (BuildInput input, BuildOutputBuilder output) async {
    final CodeConfig code = input.config.code;
    if (!input.config.buildCodeAssets || !_isSupported(code.targetOS)) {
      return;
    }
    final Uri crateRoot = input.packageRoot.resolve('rust/');
    final String target = _cargoTarget(input, code.targetOS, code.targetArchitecture);
    final Uri targetDirectory = crateRoot.resolve('target/native-assets/$target/');

    final List<String> command;
    if (code.targetOS == OS.android) {
      if ((Platform.environment['ANDROID_NDK_HOME'] ?? '').isEmpty) {
        throw StateError(
          'ANDROID_NDK_HOME is not set; cargo-ndk needs it to build '
          '$_libraryStem for Android.',
        );
      }
      command = <String>[
        'ndk',
        '-t',
        _androidAbi(code.targetArchitecture),
        'build',
        '--release',
        '--target-dir',
        targetDirectory.toFilePath(),
      ];
    } else {
      command = <String>[
        'build',
        '--release',
        '--target',
        target,
        '--target-dir',
        targetDirectory.toFilePath(),
      ];
    }
    final Process build = await Process.start(
      'cargo',
      command,
      workingDirectory: crateRoot.toFilePath(),
      mode: ProcessStartMode.inheritStdio,
    );
    if (await build.exitCode != 0) {
      throw StateError('Failed to build $_libraryStem for $target.');
    }
    final Uri library = targetDirectory.resolve(
      '$target/release/${_libraryFileName(code.targetOS)}',
    );
    if (!File.fromUri(library).existsSync()) {
      throw StateError('Cargo did not produce ${library.toFilePath()}.');
    }
    output.assets.code.add(CodeAsset(
      package: input.packageName,
      name: _assetName,
      linkMode: DynamicLoadingBundled(),
      file: library,
    ));
    _trackRustSources(input, output);
  });
}

bool _isSupported(OS os) =>
    os == OS.macOS || os == OS.linux || os == OS.iOS || os == OS.android;

String _cargoTarget(BuildInput input, OS os, Architecture a) =>
    switch ((os, a)) {
      (OS.macOS, Architecture.x64) => 'x86_64-apple-darwin',
      (OS.macOS, Architecture.arm64) => 'aarch64-apple-darwin',
      (OS.linux, Architecture.x64) => 'x86_64-unknown-linux-gnu',
      (OS.linux, Architecture.arm64) => 'aarch64-unknown-linux-gnu',
      (OS.iOS, Architecture.arm64) =>
        input.config.code.iOS.targetSdk == IOSSdk.iPhoneOS
            ? 'aarch64-apple-ios'
            : 'aarch64-apple-ios-sim',
      (OS.iOS, Architecture.x64) => 'x86_64-apple-ios',
      (OS.android, Architecture.arm64) => 'aarch64-linux-android',
      (OS.android, Architecture.arm) => 'armv7-linux-androideabi',
      (OS.android, Architecture.x64) => 'x86_64-linux-android',
      _ => throw UnsupportedError('Unsupported: ${os.name}-${a.name}'),
    };

String _androidAbi(Architecture a) => switch (a) {
      Architecture.arm64 => 'arm64-v8a',
      Architecture.arm => 'armeabi-v7a',
      Architecture.x64 => 'x86_64',
      _ => throw UnsupportedError('Unsupported Android arch: ${a.name}'),
    };

String _libraryFileName(OS os) =>
    (os == OS.macOS || os == OS.iOS)
        ? 'lib$_libraryStem.dylib'
        : 'lib$_libraryStem.so';

void _trackRustSources(BuildInput input, BuildOutputBuilder output) {
  for (final String rel in <String>['rust/']) {
    final Directory dir = Directory.fromUri(input.packageRoot.resolve(rel));
    if (!dir.existsSync()) continue;
    for (final FileSystemEntity f in dir.listSync(recursive: true, followLinks: false)) {
      if (f is! File) continue;
      final String p = f.path;
      if (p.contains('/target/') || p.contains('/.git/')) continue;
      if (p.endsWith('.rs') || p.endsWith('Cargo.toml') || p.endsWith('Cargo.lock')) {
        output.dependencies.add(f.uri);
      }
    }
  }
}
