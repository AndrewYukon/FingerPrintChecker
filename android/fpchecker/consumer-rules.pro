# fpchecker keeps nothing special: it uses org.json, HttpURLConnection and the
# Play Integrity SDK (which ships its own consumer rules).
-keep class com.fpchecker.FpChecker { public *; }
-keep class com.fpchecker.FpCheckerConfig { public *; }
-keep class com.fpchecker.FpResult { *; }
-keep class com.fpchecker.FpResult$* { *; }
-keep interface com.fpchecker.FpCallback { *; }
-keep class com.fpchecker.FpIdentifyResult { *; }
-keep class com.fpchecker.FpIdentifyResult$* { *; }
-keep interface com.fpchecker.FpIdentifyCallback { *; }
-keep class com.fpchecker.FpEventOptions { *; }
