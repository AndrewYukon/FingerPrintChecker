# @fingerprintchecker/vue

Vue plugin and composable for [FingerPrintChecker](https://fpchecker.com). Built on `@fingerprintchecker/agent`. Requires Vue 3.3 or newer.

```bash
npm install @fingerprintchecker/vue
```

```ts
import { createApp } from 'vue';
import { fpChecker } from '@fingerprintchecker/vue';

createApp(App).use(fpChecker, { publishableKey: 'pk_live_...' }).mount('#app');
```

The plugin accepts the same options as `load()` from `@fingerprintchecker/agent`: `publishableKey`, optional `endpoint`, optional `scriptUrl`. The agent loads in the browser on mount (or on the first `identify`); nothing loads during server rendering.

```vue
<script setup lang="ts">
import { useFpChecker } from '@fingerprintchecker/vue';

const props = defineProps<{ intentToken: string }>();
const { identify, data, error, isLoading } = useFpChecker(); // data, error, isLoading are refs

async function onSubmit() {
  const result = await identify({ intentToken: props.intentToken });
  await fetch('/api/signup', { method: 'POST', body: JSON.stringify({ eventId: result.eventId }) });
}
</script>
```

- `identify(opts)` passes through to the agent, updates the refs, returns the result and rethrows on failure.
- If several calls overlap, the most recently started call decides `data`.
- A failure to load the agent shows up in `error`.
- `useFpChecker()` without the plugin throws an error naming `fpChecker`.

## Nuxt

The plugin is safe to install on the server: it never loads the agent during SSR, only after the component mounts (or on the first `identify` in the browser). Use a universal plugin, no `.client` suffix and no `<ClientOnly>` needed:

```ts
// plugins/fpchecker.ts
import { fpChecker } from '@fingerprintchecker/vue';

export default defineNuxtPlugin((nuxtApp) => {
  nuxtApp.vueApp.use(fpChecker, { publishableKey: useRuntimeConfig().public.fpcheckerKey });
});
```

Calling `identify()` on the server rejects with an error whose `code` is `'ssr'`; call it from an event handler or `onMounted`.

## License

Apache-2.0
