import 'package:flutter/services.dart';

import 'config.dart';
import 'result.dart';
import 'tags.dart';

/// Thin wrapper over the native FingerPrintChecker SDKs.
class FingerPrintChecker {
  FingerPrintChecker(this.config, {MethodChannel? channel})
      : _channel = channel ?? const MethodChannel(channelName);

  static const String channelName = 'com.fpchecker/flutter';

  final FpConfig config;
  final MethodChannel _channel;

  Future<FpIdentifyResult> identify(
    String intentToken, {
    String? linkedId,
    Map<String, Object?>? tags,
  }) async {
    if (intentToken.isEmpty) return const FpFailure('bad_intent_token', 0);
    if (config.publishableKey.isEmpty) return const FpFailure('bad_config', 0);
    if (tags != null && !isJsonable(tags)) {
      return const FpFailure('invalid_tags', 0);
    }
    try {
      final reply = await _channel.invokeMethod<Object?>('identify', {
        'config': config.toMap(),
        'intentToken': intentToken,
        if (linkedId != null) 'linkedId': linkedId,
        if (tags != null) 'tags': tags,
      });
      return _mapReply(reply);
    } catch (_) {
      // Covers PlatformException, MissingPluginException and anything else.
      return const FpFailure('bridge_error', 0);
    }
  }
}

const _bridgeError = FpFailure('bridge_error', 0);

String? _str(Object? v) => v is String ? v : null;

/// Thrown internally when a numeric field is not an integral value.
class _BadNumber implements Exception {
  const _BadNumber();
}

/// Absent or non-numeric -> null. Integral num (int, or double without a
/// fractional part) -> int. Fractional or non-finite -> [_BadNumber].
int? _int(Object? v) {
  if (v is int) return v;
  if (v is double) {
    if (v.isFinite && v == v.truncateToDouble()) return v.toInt();
    throw const _BadNumber();
  }
  return null;
}
List<String> _strList(Object? v) =>
    v is List ? v.whereType<String>().toList(growable: false) : const [];

FpIdentifyResult _mapReply(Object? reply) {
  try {
    return _mapReplyUnchecked(reply);
  } on _BadNumber {
    return _bridgeError;
  }
}

FpIdentifyResult _mapReplyUnchecked(Object? reply) {
  if (reply is! Map) return _bridgeError;
  final ok = reply['ok'];
  if (ok is! bool) return _bridgeError;
  if (!ok) {
    final reason = reply['reason'];
    if (reason is! String) return _bridgeError;
    return FpFailure(reason, _int(reply['httpStatus']) ?? 0);
  }
  final visitorId = reply['visitorId'];
  final attestation = reply['attestation'];
  if (attestation is! String || attestation.isEmpty) return _bridgeError;
  if (visitorId != null && visitorId is! String) return _bridgeError;
  final isNew = reply['isNew'];
  return FpSuccess(
    visitorId: visitorId as String?,
    attestation: attestation,
    eventId: _str(reply['eventId']),
    trustScore: _int(reply['trustScore']),
    identityConfidence: _int(reply['identityConfidence']),
    isNew: isNew is bool ? isNew : null,
    trustDeductions: _strList(reply['trustDeductions']),
    shadowDeductions: _strList(reply['shadowDeductions']),
    proofStatus: _str(reply['proofStatus']),
    expiresIn: _int(reply['expiresIn']),
    rulesVersion: _str(reply['rulesVersion']),
    sealedResult: _str(reply['sealedResult']),
    rawJson: _str(reply['rawJson']) ?? '',
  );
}
