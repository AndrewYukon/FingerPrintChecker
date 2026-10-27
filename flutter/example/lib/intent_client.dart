import 'dart:convert';
import 'dart:io';

sealed class IntentOutcome {
  const IntentOutcome();
}

class IntentToken extends IntentOutcome {
  const IntentToken(this.token);
  final String token;
}

class IntentFailure extends IntentOutcome {
  const IntentFailure(this.reason);
  final String reason;
}

/// POSTs [url] and reads `{intentToken}` from the reply.
Future<IntentOutcome> fetchIntent(String url) async {
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 10);
  try {
    final request = await client.postUrl(Uri.parse(url));
    request.headers.contentType = ContentType.json;
    request.write('{}');
    final response = await request.close().timeout(const Duration(seconds: 10));
    final body = await response.transform(utf8.decoder).join();
    final Object? json = jsonDecode(body);
    final token = json is Map ? json['intentToken'] : null;
    if (response.statusCode == 200 && token is String && token.isNotEmpty) {
      return IntentToken(token);
    }
    final error = json is Map ? json['error'] : null;
    return IntentFailure(error is String && error.isNotEmpty ? error : 'bad_response');
  } on FormatException {
    return const IntentFailure('bad_response');
  } catch (_) {
    return const IntentFailure('network');
  } finally {
    client.close(force: true);
  }
}
