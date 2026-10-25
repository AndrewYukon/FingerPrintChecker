// Node >=22 ships its own (file-backed, experimental) localStorage global that shadows happy-dom's.
// Pin the browser-style Storage from happy-dom so tests behave the same on every Node version.
import { Window } from 'happy-dom';

const host = new Window();
for (const name of ['localStorage', 'sessionStorage'] as const) {
  const value = host[name];
  for (const target of [globalThis, window]) {
    Object.defineProperty(target, name, { value, configurable: true, writable: true });
  }
}
