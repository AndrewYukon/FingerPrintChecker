import 'package:flutter/material.dart';

import 'intent_client.dart';

import 'package:fingerprintchecker/fingerprintchecker.dart';

const _publishableKey = String.fromEnvironment('FPC_PK');
const _intentUrl = String.fromEnvironment('FPC_INTENT_URL');

void main() {
  runApp(const ExampleApp());
}

class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key, this.identify = runIdentify});

  /// Injectable for tests; defaults to the real intent + identify flow.
  final Future<String> Function() identify;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'FingerPrintChecker example',
      theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
      home: HomePage(identify: identify),
    );
  }
}

/// Mints an intent from [_intentUrl], runs identify, returns text to show.
Future<String> runIdentify() async {
  if (_publishableKey.isEmpty || _intentUrl.isEmpty) {
    return 'bad_config: pass --dart-define=FPC_PK and --dart-define=FPC_INTENT_URL';
  }
  final intent = await fetchIntent(_intentUrl);
  if (intent is IntentFailure) return intent.reason;
  final checker = FingerPrintChecker(
    const FpConfig(publishableKey: _publishableKey),
  );
  final result = await checker.identify((intent as IntentToken).token);
  return switch (result) {
    FpSuccess(:final eventId, :final visitorId) => describeSuccess(
      eventId,
      visitorId,
    ),
    FpFailure(:final reason, :final httpStatus) => '$reason ($httpStatus)',
  };
}

/// eventId is what your backend sends to the server API; visitorId arrives only with scoreDetails.
String describeSuccess(String? eventId, String? visitorId) {
  final lines = [
    if (eventId != null) 'eventId: $eventId',
    if (visitorId != null) 'visitorId: $visitorId',
  ];
  return lines.isEmpty ? 'ok' : lines.join('\n');
}

class HomePage extends StatefulWidget {
  const HomePage({super.key, required this.identify});

  final Future<String> Function() identify;

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  String _text = 'Tap Identify';
  bool _busy = false;

  Future<void> _run() async {
    setState(() => _busy = true);
    String out;
    try {
      out = await widget.identify();
    } catch (e) {
      out = 'bridge_error';
    }
    if (!mounted) return;
    setState(() {
      _text = out;
      _busy = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('FingerPrintChecker')),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              FilledButton(
                onPressed: _busy ? null : _run,
                child: const Text('Identify'),
              ),
              const SizedBox(height: 16),
              SelectableText(_text, key: const Key('result')),
            ],
          ),
        ),
      ),
    );
  }
}
