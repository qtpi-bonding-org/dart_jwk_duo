/// Serves a release build of example/conformance_app to headless Chrome and
/// checks its report, including interop with this (native) process.
/// Run through `tool/verify.sh web`.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:dart_jwk_duo/testing.dart';

const String _web = 'example/conformance_app/build/web';

Future<void> main() async {
  final String chrome = Platform.environment['CHROME'] ??
      (Platform.isMacOS ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' : 'google-chrome');
  final String nativeBundle = await createInteropBundle();
  final Completer<String> posted = Completer<String>();
  final Map<String, int> hits = <String, int>{};
  final HttpServer server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  server.listen((HttpRequest q) async {
    final HttpResponse p = q.response;
    String path = q.uri.path == '/' ? '/index.html' : q.uri.path;
    final int n = hits[path] = (hits[path] ?? 0) + 1;
    p.headers.set('cache-control', 'no-store');
    // No COOP/COEP. No eval and no workers allowed.
    p.headers.set('content-security-policy',
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'none'; style-src 'self' 'unsafe-inline'");
    try {
      if (path == '/report') {
        final String body = await utf8.decoder.bind(q).join();
        if (!posted.isCompleted) posted.complete(body);
      } else if (path == '/interop.json') {
        p.write(nativeBundle);
      } else {
        final bool script = path == '/pkg/dart_jwk_duo_bridge.js';
        final bool wasm = path == '/pkg/dart_jwk_duo_bridge_bg.wasm';
        if (script && n == 2) {
          // As a single-page-app server would: 200, HTML, sniffable.
          path = '/index.html';
          p.headers.removeAll('x-content-type-options');
        }
        final File f = File('$_web$path');
        if (((script || wasm) && n == 1) || path.contains('..') || !f.existsSync()) {
          p.statusCode = HttpStatus.notFound;
        } else {
          p.headers.contentType = switch (path.split('.').last) {
            'html' => ContentType.html,
            'js' || 'mjs' => ContentType('text', 'javascript'),
            'wasm' => ContentType('application', 'wasm'),
            'json' => ContentType.json,
            _ => ContentType.binary,
          };
          await p.addStream(f.openRead());
        }
      }
    } finally {
      await p.close();
    }
  });

  final Directory profile = Directory.systemTemp.createTempSync('dart_jwk_duo_chrome');
  final StringBuffer log = StringBuffer();
  final Process browser = await Process.start(chrome, <String>[
    '--headless', '--no-first-run', '--no-default-browser-check', '--enable-logging=stderr',
    '--user-data-dir=${profile.path}', 'http://127.0.0.1:${server.port}/', //
  ]);
  browser.stderr.transform(utf8.decoder).listen(log.write);
  browser.stdout.transform(utf8.decoder).listen(log.write);
  final List<String> problems = <String>[];
  void expect(String what, Object? got, Object? want) {
    stdout.writeln('$what: ${jsonEncode(got)}');
    if (jsonEncode(got) != jsonEncode(want)) problems.add('$what: got ${jsonEncode(got)}, want ${jsonEncode(want)}');
  }

  try {
    final Map<String, dynamic> r =
        jsonDecode(await posted.future.timeout(const Duration(seconds: 120))) as Map<String, dynamic>;
    expect('error', r['error'], null);
    expect('crossOriginIsolated', r['crossOriginIsolated'], false);
    expect('loadFailures', r['loadFailures'], <String>['StateError', 'StateError', 'StateError']);
    expect('script requests', hits['/pkg/dart_jwk_duo_bridge.js'], 3);
    expect('wasm requests', hits['/pkg/dart_jwk_duo_bridge_bg.wasm'], 2);
    expect('conformance', r['conformance'],
        <String, Object>{'files': 11, 'run': 384, 'passed': 384, 'skipped': 8, 'failures': <String>[]});
    expect('native bundle checked on web', r['interopChecks'], 22);
    expect('web bundle checked on native', await checkInteropBundle(r['interopBundle'] as String? ?? '{}'), 22);
    expect('distinctKeys', r['distinctKeys'], true);
    expect('verifyKeyDuo', r['verifyKeyDuo'], true);
    expect('useAfterDispose', r['useAfterDispose'], 'StateError');
    expect('badInput', r['badInput'], 'FormatException');
    expect('noRng fails', r['noRng'] != 'nothing', true);
    // Reported, not asserted: what a Rust panic leaves behind.
    stdout.writeln('noRng threw: ${r['noRng']}\nnext call: ${r['afterPanic']}');
  } catch (e) {
    problems.add('$e');
  } finally {
    browser.kill();
    await browser.exitCode;
    await server.close(force: true);
    try {
      profile.deleteSync(recursive: true);
    } on FileSystemException {
      // Chrome helpers may still hold files; the OS temp dir is cleaned anyway.
    }
  }
  if (problems.isNotEmpty) {
    stdout.writeln('--- chrome log\n$log--- problems\n${problems.join('\n')}');
    exitCode = 1;
  } else {
    stdout.writeln('All tests passed (web)');
  }
  exit(exitCode);
}
