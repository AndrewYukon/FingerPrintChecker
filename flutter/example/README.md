# FingerPrintChecker Flutter example

Needs a publishable key and a URL on your backend that returns an intent token.
Pass both at run time with `--dart-define` (nothing is stored in the repo):

```sh
flutter run \
  --dart-define=FPC_PK=pk_live_your_key \
  --dart-define=FPC_INTENT_URL=https://your-backend.example.com/fpchecker/intent
```

Pick the target with `-d`: an Android emulator id or an iOS simulator id (`flutter devices` lists them).
Without the two defines the app shows `bad_config`.
