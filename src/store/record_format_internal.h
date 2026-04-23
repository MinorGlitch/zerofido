#pragma once

#include <stdbool.h>

#include "../zerofido_types.h"

bool zf_store_record_format_encode(const ZfCredentialRecord *record, uint8_t *out,
                                   size_t *out_size);
