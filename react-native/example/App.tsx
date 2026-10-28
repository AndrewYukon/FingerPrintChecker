import React, {useState} from 'react';
import {Button, NativeModules, SafeAreaView, StyleSheet, Text} from 'react-native';
import {FingerPrintChecker} from '@fingerprintchecker/react-native';
import {FPC_INTENT_URL, FPC_PK} from './config';

/** POST the intent URL and read `{intentToken}`; mirrors the Android demo's IntentClient. */
async function fetchIntentToken(url: string): Promise<string> {
  const response = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: '{}',
  });
  const body = (await response.json().catch(() => ({}))) as {intentToken?: string; error?: string};
  if (response.status === 200 && body.intentToken) {
    return body.intentToken;
  }
  throw new Error(body.error ?? `intent_${response.status}`);
}

const nativeLinked = NativeModules.FingerPrintCheckerModule != null;

const checker = new FingerPrintChecker({publishableKey: FPC_PK});

// eventId is what your backend sends to the server API; visitorId arrives only with scoreDetails.
function describeSuccess(eventId?: string, visitorId?: string): string {
  const lines = [eventId && `eventId: ${eventId}`, visitorId && `visitorId: ${visitorId}`].filter(Boolean);
  return lines.length ? lines.join('\n') : 'ok';
}

export default function App() {
  const [result, setResult] = useState('');
  const [busy, setBusy] = useState(false);

  const run = async () => {
    setBusy(true);
    try {
      const token = await fetchIntentToken(FPC_INTENT_URL);
      const r = await checker.identify(token);
      setResult(r.ok ? describeSuccess(r.eventId, r.visitorId) : `failed: ${r.reason} (${r.httpStatus})`);
    } catch (e) {
      setResult(`failed: ${e instanceof Error ? e.message : 'network'}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <SafeAreaView style={styles.root}>
      <Text testID="native-status">{nativeLinked ? 'native module: linked' : 'native module: not linked'}</Text>
      <Button title="Identify" onPress={run} disabled={busy} testID="identify" />
      <Text style={styles.result} testID="result">
        {result}
      </Text>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: {flex: 1, justifyContent: 'center', padding: 24},
  result: {marginTop: 24, fontSize: 16},
});
