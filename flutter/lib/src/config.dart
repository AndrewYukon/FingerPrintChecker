/// Configuration for [FingerPrintChecker]. Fields the current platform lacks are ignored.
class FpConfig {
  const FpConfig({
    required this.publishableKey,
    this.baseUrl,
    this.powDifficulty,
    this.integrityProbes,
    this.cloudProjectNumber,
    this.integrityTimeoutMillis,
    this.useAppAttest,
    this.useDeviceCheck,
  });

  final String publishableKey;
  final String? baseUrl;
  final int? powDifficulty;
  final bool? integrityProbes;

  /// Android only.
  final int? cloudProjectNumber;

  /// Android only.
  final int? integrityTimeoutMillis;

  /// iOS only.
  final bool? useAppAttest;

  /// iOS only.
  final bool? useDeviceCheck;

  /// Bridge representation; null fields are omitted.
  Map<String, Object?> toMap() {
    final entries = <String, Object?>{
      'publishableKey': publishableKey,
      'baseUrl': baseUrl,
      'powDifficulty': powDifficulty,
      'integrityProbes': integrityProbes,
      'cloudProjectNumber': cloudProjectNumber,
      'integrityTimeoutMillis': integrityTimeoutMillis,
      'useAppAttest': useAppAttest,
      'useDeviceCheck': useDeviceCheck,
    };
    return {
      for (final e in entries.entries)
        if (e.value != null) e.key: e.value,
    };
  }
}
