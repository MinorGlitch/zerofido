#include "../zerofido_pin.h"

/*
 * PIN flow behavior is split by ownership in src/pin/core:
 * token.c handles pinUvAuthToken validation, retry.c owns retry/block accounting,
 * plaintext.c owns PIN policy and hashing, and lifecycle.c owns init/reset.
 */
