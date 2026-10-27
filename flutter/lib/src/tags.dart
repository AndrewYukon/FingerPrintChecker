/// True when [value] is JSON-able: String, finite num, bool, null, or a
/// List / Map with String keys of the same. Cycles are rejected.
bool isJsonable(Object? value, [Set<Object>? seen]) {
  if (value == null || value is String || value is bool) return true;
  if (value is num) return value.isFinite;
  if (value is! List && value is! Map) return false;
  final visiting = seen ?? Set<Object>.identity();
  if (!visiting.add(value)) return false;
  try {
    if (value is List) return value.every((v) => isJsonable(v, visiting));
    final map = value as Map;
    return map.entries
        .every((e) => e.key is String && isJsonable(e.value, visiting));
  } finally {
    visiting.remove(value);
  }
}
