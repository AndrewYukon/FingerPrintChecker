import 'package:fingerprintchecker/fingerprintchecker.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

const _ch = MethodChannel('com.fpchecker/flutter');

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  final calls = <MethodCall>[];

  void mock(Future<Object?> Function(MethodCall) h) {
    calls.clear();
    messenger.setMockMethodCallHandler(_ch, (c) {
      calls.add(c);
      return h(c);
    });
  }

  tearDown(() => messenger.setMockMethodCallHandler(_ch, null));

  const cfg = FpConfig(publishableKey: 'pk_test');

  test('FpConfig.toMap omits nulls', () {
    expect(cfg.toMap(), {'publishableKey': 'pk_test'});
    expect(
      const FpConfig(
        publishableKey: 'k',
        baseUrl: 'https://x',
        powDifficulty: 3,
        integrityProbes: false,
        cloudProjectNumber: 7,
        integrityTimeoutMillis: 100,
        useAppAttest: true,
        useDeviceCheck: false,
      ).toMap(),
      {
        'publishableKey': 'k',
        'baseUrl': 'https://x',
        'powDifficulty': 3,
        'integrityProbes': false,
        'cloudProjectNumber': 7,
        'integrityTimeoutMillis': 100,
        'useAppAttest': true,
        'useDeviceCheck': false,
      },
    );
  });

  test('maps a full success reply and sends the right args', () async {
    mock((_) async => {
          'ok': true,
          'visitorId': 'v1',
          'attestation': 'att',
          'eventId': 'e1',
          'trustScore': 80.0, // integral double
          'identityConfidence': 90, // int
          'isNew': true,
          'trustDeductions': ['a', 'b'],
          'shadowDeductions': ['c'],
          'proofStatus': 'ok',
          'expiresIn': 60,
          'rulesVersion': 'r1',
          'sealedResult': 's',
          'rawJson': '{}',
        });
    final r = await FingerPrintChecker(cfg)
        .identify('tok', linkedId: 'L', tags: {'k': 1});
    final s = r as FpSuccess;
    expect(s.visitorId, 'v1');
    expect(s.attestation, 'att');
    expect(s.trustScore, 80);
    expect(s.trustScore, isA<int>());
    expect(s.identityConfidence, 90);
    expect(s.isNew, true);
    expect(s.trustDeductions, ['a', 'b']);
    expect(s.shadowDeductions, ['c']);
    expect(s.rawJson, '{}');
    expect(calls.single.method, 'identify');
    expect(calls.single.arguments, {
      'config': {'publishableKey': 'pk_test'},
      'intentToken': 'tok',
      'linkedId': 'L',
      'tags': {'k': 1},
    });
  });

  test('minimal success: absent lists become []', () async {
    mock((_) async => {'ok': true, 'visitorId': 'v', 'attestation': 'a'});
    final s = await FingerPrintChecker(cfg).identify('t') as FpSuccess;
    expect(s.trustDeductions, isEmpty);
    expect(s.shadowDeductions, isEmpty);
    expect(s.eventId, isNull);
    expect(s.rawJson, '');
    expect(calls.single.arguments, {
      'config': {'publishableKey': 'pk_test'},
      'intentToken': 't',
    });
  });

  test('maps a failure reply (double httpStatus tolerated)', () async {
    mock((_) async => {'ok': false, 'reason': 'http_error', 'httpStatus': 429});
    var f = await FingerPrintChecker(cfg).identify('t') as FpFailure;
    expect(f.reason, 'http_error');
    expect(f.httpStatus, 429);
    mock((_) async => {'ok': false, 'reason': 'x', 'httpStatus': 500.0});
    f = await FingerPrintChecker(cfg).identify('t') as FpFailure;
    expect(f.httpStatus, 500);
  });

  test('invalid tags fail locally and never call the bridge', () async {
    mock((_) async => {'ok': true, 'visitorId': 'v', 'attestation': 'a'});
    final c = FingerPrintChecker(cfg);
    for (final bad in <Object?>[
      DateTime(2026),
      Object(),
      double.nan,
      double.infinity,
    ]) {
      final r = await c.identify('t', tags: {'k': bad}) as FpFailure;
      expect(r.reason, 'invalid_tags');
      expect(r.httpStatus, 0);
    }
    expect(calls, isEmpty);
  });

  test('empty publishableKey is bad_config without bridge call', () async {
    mock((_) async => null);
    final r = await FingerPrintChecker(const FpConfig(publishableKey: ''))
        .identify('t') as FpFailure;
    expect(r.reason, 'bad_config');
    expect(calls, isEmpty);
  });

  test('bridge_error for PlatformException', () async {
    mock((_) async => throw PlatformException(code: 'boom'));
    final r = await FingerPrintChecker(cfg).identify('t') as FpFailure;
    expect((r.reason, r.httpStatus), ('bridge_error', 0));
  });

  test('bridge_error for MissingPluginException', () async {
    mock((_) async => throw MissingPluginException());
    final r = await FingerPrintChecker(cfg).identify('t') as FpFailure;
    expect(r.reason, 'bridge_error');
  });

  test('visitorId is optional: absent or null maps to null', () async {
    for (final r in <Map<String, Object?>>[
      {'ok': true, 'attestation': 'a'},
      {'ok': true, 'visitorId': null, 'attestation': 'a'},
    ]) {
      mock((_) async => r);
      final s = await FingerPrintChecker(cfg).identify('t') as FpSuccess;
      expect(s.visitorId, isNull);
      expect(s.attestation, 'a');
    }
  });

  test('bridge_error for malformed replies', () async {
    final bad = <Object?>[
      null,
      'str',
      <String, Object?>{'visitorId': 'v', 'attestation': 'a'},
      {'ok': true, 'visitorId': 'v'},
      {'ok': true, 'visitorId': 'v', 'attestation': ''},
      {'ok': true, 'visitorId': 'v', 'attestation': 5},
      {'ok': false},
      {'ok': 'yes'},
    ];
    for (final b in bad) {
      mock((_) async => b);
      final r = await FingerPrintChecker(cfg).identify('t') as FpFailure;
      expect(r.reason, 'bridge_error', reason: '$b');
    }
  });

  test('fractional or non-finite numeric fields are bridge_error', () async {
    final base = {'ok': true, 'visitorId': 'v', 'attestation': 'a'};
    final bad = <Map<String, Object?>>[
      {...base, 'trustScore': 80.5},
      {...base, 'identityConfidence': double.nan},
      {...base, 'expiresIn': double.infinity},
      {'ok': false, 'reason': 'x', 'httpStatus': double.nan},
      {'ok': false, 'reason': 'x', 'httpStatus': double.infinity},
      {'ok': false, 'reason': 'x', 'httpStatus': 429.5},
    ];
    for (final b in bad) {
      mock((_) async => b);
      final r = await FingerPrintChecker(cfg).identify('t') as FpFailure;
      expect(r.reason, 'bridge_error', reason: '$b');
    }
  });

  test('non-String-key tags are invalid_tags, bridge not called', () async {
    mock((_) async => {'ok': true, 'visitorId': 'v', 'attestation': 'a'});
    final r = await FingerPrintChecker(cfg).identify('t', tags: {
      'k': <Object?, Object?>{1: 'x'},
    }) as FpFailure;
    expect(r.reason, 'invalid_tags');
    expect(calls, isEmpty);
  });

  test('absurdly deep tags are invalid_tags, never a thrown error', () async {
    mock((_) async => {'ok': true, 'visitorId': 'v', 'attestation': 'a'});
    Object? deep = 'leaf';
    for (var i = 0; i < 1000000; i++) {
      deep = <String, Object?>{'k': deep};
    }
    final r = await FingerPrintChecker(cfg)
        .identify('t', tags: {'deep': deep}) as FpFailure;
    expect(r.reason, 'invalid_tags');
    expect(calls, isEmpty);
  });

  test('custom channel is honoured', () async {
    const other = MethodChannel('other');
    var hit = false;
    messenger.setMockMethodCallHandler(other, (_) async {
      hit = true;
      return {'ok': true, 'visitorId': 'v', 'attestation': 'a'};
    });
    addTearDown(() => messenger.setMockMethodCallHandler(other, null));
    await FingerPrintChecker(cfg, channel: other).identify('t');
    expect(hit, isTrue);
  });
}
