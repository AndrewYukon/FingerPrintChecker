/// Outcome of an identify call.
sealed class FpIdentifyResult {
  const FpIdentifyResult();
}

final class FpSuccess extends FpIdentifyResult {
  const FpSuccess({
    this.visitorId,
    required this.attestation,
    this.eventId,
    this.trustScore,
    this.identityConfidence,
    this.isNew,
    this.trustDeductions = const [],
    this.shadowDeductions = const [],
    this.proofStatus,
    this.expiresIn,
    this.rulesVersion,
    this.sealedResult,
    this.rawJson = '',
  });

  /// Present only when the project enables score details; null otherwise.
  final String? visitorId;
  final String attestation;
  final String? eventId;
  final int? trustScore;
  final int? identityConfidence;
  final bool? isNew;
  final List<String> trustDeductions;
  final List<String> shadowDeductions;
  final String? proofStatus;
  final int? expiresIn;
  final String? rulesVersion;
  final String? sealedResult;
  final String rawJson;
}

final class FpFailure extends FpIdentifyResult {
  const FpFailure(this.reason, this.httpStatus);

  final String reason;
  final int httpStatus;
}
