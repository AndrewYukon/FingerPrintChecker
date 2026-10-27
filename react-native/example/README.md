# FingerPrintChecker React Native example

1. Create your untracked config: `cp config.example.ts config.ts`, then set `FPC_PK` (your publishable key)
   and `FPC_INTENT_URL` (a URL on your backend that returns an intent token). `config.ts` is git-ignored.
2. `npm install`
3. iOS simulator: `cd ios && pod install && cd ..`, then `npm run ios`.
4. Android emulator: start one, then `npm run android`.
