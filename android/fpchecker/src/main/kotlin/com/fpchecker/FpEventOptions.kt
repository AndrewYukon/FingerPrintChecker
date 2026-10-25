package com.fpchecker

/**
 * Optional fields stored on the event an identify call writes. They are client-supplied (no platform proof covers
 * them) and are never part of the signed or attested bytes; read them back with your secret key.
 *
 * A value that breaks a rule makes `identify` return a `Failure` (`invalid_linked_id` / `invalid_tags`)
 * before any network call. `null` means "not set": nothing is sent.
 *
 * @property linkedId your own identifier for the event (order id, user id...): 1 to 256 characters, no control characters.
 * @property tags a map of at most 4096 bytes as JSON, nested at most 3 levels (a list counts as a level). Values may be
 *   `String`, `Boolean`, finite numbers, `null`, `Map<String, ...>` and `List`/`Array` of those.
 */
public data class FpEventOptions @JvmOverloads constructor(
    val linkedId: String? = null,
    val tags: Map<String, Any?>? = null,
)
