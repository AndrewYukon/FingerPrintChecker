# @fpchecker/vue

Vue plugin and composable for [FingerPrintChecker](https://fpchecker.com). Built on `@fpchecker/agent`. Requires Vue 3.3 or newer.

```bash
npm install @fpchecker/vue
```

```ts
import { createApp } from 'vue';
import { fpChecker } from '@fpchecker/vue';

createApp(App).use(fpChecker, { publishableKey: 'pk_live_...' }).mount('#app');
```

The plugin accepts the same options as `load()` from `@fpchecker/agent`: `publishableKey`, optional `endpoint`, optional `scriptUrl`. The agent loads in the browser on mount (or on the first `identify`); nothing loads during server rendering.

```vue
<script setup lang="ts">
import { useFpChecker } from '@fpchecker/vue';

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

Register it in a client-only plugin so it never runs on the server:

```ts
// plugins/fpchecker.client.ts
import { fpChecker } from '@fpchecker/vue';

export default defineNuxtPlugin((nuxtApp) => {
  nuxtApp.vueApp.use(fpChecker, { publishableKey: useRuntimeConfig().public.fpcheckerKey });
});
```

Components that call `useFpChecker()` must render on the client (wrap them in `<ClientOnly>`), because the plugin is not installed during SSR.

## License

Apache-2.0
