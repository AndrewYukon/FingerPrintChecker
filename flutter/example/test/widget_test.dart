import 'package:example/main.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('shows the identify outcome in the result text', (tester) async {
    await tester.pumpWidget(ExampleApp(identify: () async => 'v_123'));
    await tester.tap(find.text('Identify'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('result')), findsOneWidget);
    expect(find.text('v_123'), findsOneWidget);
  });

  test(
    'describeSuccess shows eventId, and visitorId only when the server sent it',
    () {
      expect(describeSuccess('ev_1', null), 'eventId: ev_1');
      expect(describeSuccess('ev_1', 'v_1'), 'eventId: ev_1\nvisitorId: v_1');
      expect(describeSuccess(null, null), 'ok');
    },
  );
}
