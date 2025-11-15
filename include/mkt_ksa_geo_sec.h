/* MKT KSA Geolocation Security – C Header (Auto-generated) */
/* Zero-deps core; enable `ffi_c` to expose FFI symbols. */

#ifndef MKT_KSA_GEO_SEC_H
#define MKT_KSA_GEO_SEC_H

#pragma once

/* Generated with cbindgen:0.29.0 */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define EPS_F32 1.0e-6

#define EPS_F64 1.0e-12

char *generate_adaptive_fingerprint(const char *os, const char *device_info, const char *env_data);

void free_fingerprint_string(char *ptr);

const char *mkt_version_string(void);

int32_t mkt_hmac_sha512(const uint8_t *data_ptr,
                        size_t data_len,
                        const uint8_t *key_ptr,
                        size_t key_len,
                        uint8_t *out_ptr,
                        size_t out_len);

#endif  /* MKT_KSA_GEO_SEC_H */

/* End of header */
