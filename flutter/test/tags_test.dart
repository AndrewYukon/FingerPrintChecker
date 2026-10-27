import 'package:fingerprintchecker/src/tags.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('accepts json-able values', () {
    expect(
      isJsonable({
        'a': 1,
        'b': 1.5,
        'c': 'x',
        'd': true,
        'e': null,
        'f': [1, 'a', {'g': 2}],
      }),
      isTrue,
    );
  });

  test('rejects DateTime, Object, NaN, Infinity, nested bad values', () {
    expect(isJsonable({'a': DateTime(2026)}), isFalse);
    expect(isJsonable({'a': Object()}), isFalse);
    expect(isJsonable({'a': double.nan}), isFalse);
    expect(isJsonable({'a': double.infinity}), isFalse);
    expect(isJsonable({'a': [1, Object()]}), isFalse);
  });

  test('rejects non-string map keys and cycles', () {
    expect(isJsonable({'a': <Object?, Object?>{1: 'x'}}), isFalse);
    final cyc = <String, Object?>{};
    cyc['self'] = cyc;
    expect(isJsonable(cyc), isFalse);
  });

  test('shared (non-cyclic) references are fine', () {
    final shared = [1, 2];
    expect(isJsonable({'a': shared, 'b': shared}), isTrue);
  });
}
