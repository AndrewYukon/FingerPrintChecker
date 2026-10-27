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
    } on PlatformException {
      return const FpFailure('bridge_error', 0);
    } on MissingPluginException {
      return const FpFailure('bridge_error', 0);
    } catch (_) {
      return const FpFailure('bridge_error', 0);
    }
  }
}

const _bridgeError = FpFailure('bridge_error', 0);

String? _str(Object? v) => v is String ? v : null;
num? _num(Object? v) => v is num ? v : null;
List<String> _strList(Object? v) =>
    v is List ? v.whereType<String>().toList(growable: false) : const [];

FpIdentifyResult _mapReply(Object? reply) {
  if (reply is! Map) return _bridgeError;
  final ok = reply['ok'];
  if (ok is! bool) return _bridgeError;
  if (!ok) {
    final reason = reply['reason'];
    if (reason is! String) return _bridgeError;
    return FpFailure(reason, _num(reply['httpStatus'])?.toInt() ?? 0);
  }
  final visitorId = reply['visitorId'];
  final attestation = reply['attestation'];
  if (visitorId is! String || attestation is! String) return _bridgeError;
  final isNew = reply['isNew'];
  return FpSuccess(
    visitorId: visitorId,
    attestation: attestation,
    eventId: _str(reply['eventId']),
    trustScore: _num(reply['trustScore']),
    identityConfidence: _num(reply['identityConfidence']),
    isNew: isNew is bool ? isNew : null,
    trustDeductions: _strList(reply['trustDeductions']),
    shadowDeductions: _strList(reply['shadowDeductions']),
    proofStatus: _str(reply['proofStatus']),
    expiresIn: _num(reply['expiresIn']),
    rulesVersion: _str(reply['rulesVersion']),
    sealedResult: _str(reply['sealedResult']),
    rawJson: _str(reply['rawJson']) ?? '',
  );
}
