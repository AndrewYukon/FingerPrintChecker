# Task 6 report: React Native Android module and example

## Built
- `react-native/android/build.gradle` (namespace com.fpchecker.reactnative, minSdk 23, `api com.fpchecker:fpchecker-android:0.7.0`, coroutines 1.9.0, `com.facebook.react:react-android`).
- `Bridge.kt`: pure logic on `Map<String, Any?>`: `configFrom`, `replyOf`, `failureReply`, `Identifier` seam, `IdentifyHandler` (per-canonical-config instance map in a ConcurrentHashMap via computeIfAbsent, never throws except CancellationException).
- `FingerPrintCheckerModule.kt` (name `FingerPrintCheckerModule`, thin ReadableMap/WritableMap adapter, `CoroutineScope(SupervisorJob()+Dispatchers.Main)`, always resolves, invalidate() cancels and closes), `FingerPrintCheckerPackage.kt`.
- `BridgeTest.kt`: 21 JVM tests.
- `react-native/example/` (RN 0.76.9, `file:..` dependency, Metro configured for the linked lib, one-button App.tsx mirroring IntentClient, `config.example.ts` committed, `config.ts` git-ignored).
- `react-native/package.json`: devDependencies `react-native` 0.76.9 and `react` 18.3.1.

## Results
- Red: with Bridge.kt/Module removed, `:fingerprintchecker_react-native:testDebugUnitTest` failed to compile (Unresolved reference).
- Green: same command BUILD SUCCESSFUL; BridgeTest tests=21 failures=0 errors=0.
- `cd react-native/example/android && ./gradlew assembleDebug`: BUILD SUCCESSFUL (module classes present in the APK dex).
- `npm run typecheck` pass, `npm test` 15/15 pass (library); `npx tsc --noEmit` in example passes.
- Gradle project name of the autolinked library: `:fingerprintchecker_react-native`.

## Notes / deviations
- Task 3 (flutter Bridge.kt) does not exist in this worktree, so Bridge.kt was written from the brief and SDK source.
- SDK only checks http(s); the "http only on loopback" rule is enforced in `configFrom` (localhost, 127.0.0.1, ::1; host compared exactly, so localhost.evil.com is rejected). 10.0.2.2 is NOT allowed.
- `sealKey` is never read. Whole-number Doubles in tags are normalised to Long so they serialise as integers.
- Environment: an empty half-installed NDK dir (from an aborted Gradle auto-download) blocked builds; removed it and installed `ndk;26.1.10909125` with sdkmanager. RN 0.76 template uses Kotlin 1.9.25; it consumes the Kotlin 2.0.21 SDK without problems.
- Example ios/ folder is the untouched generator output (no pods installed) for Task 7.

## Concerns
- Example not run on a device/emulator (build only).

## Fix round 1
- Bridge.kt: `handle()` wraps everything in `withContext(Dispatchers.Default)` plus catch Throwable -> bridge_error (CancellationException rethrown); only IAE from `configFrom` -> bad_config. Factory/FpChecker construction now runs off the main thread, still atomic via computeIfAbsent.
- Instance key is `instanceKey(FpCheckerConfig)` (parsed Android fields), so iOS-only/unknown keys do not create instances.
- Module: `OnceResolver` guarantees exactly-once resolve with a bridge_error fallback if map conversion throws; identify after `invalidate()` resolves bridge_error; cancellation (in-flight or before start, via `invokeOnCompletion`) resolves bridge_error.
- Tests: 28 (was 21): real multi-thread race (16 calls, slow factory, latch), ignored-key instance test, factory ISE and self-referencing-tags StackOverflowError -> bridge_error, tag cases (nested list/map, null, fractional, non-map dropped), OnceResolver exactly-once and conversion fallback.
- Not testable on plain JVM: `ReadableMap.toHashMap` / `Arguments.makeNativeMap` themselves need the RN runtime; only the fallback logic (OnceResolver) is tested. Module-level invalidate paths are likewise untested.
- Tests were added together with the fix rather than watched failing first.
- Results: BridgeTest 28/28, assembleDebug OK, `npm run typecheck` OK, `npm test` 15/15.
