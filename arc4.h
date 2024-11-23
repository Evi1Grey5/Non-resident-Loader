#pragma once

namespace ARC4 {
    typedef struct mbedtls_arc4_context
    {
        int x;                      /*!< permutation index */
        int y;                      /*!< permutation index */
        unsigned char m[256];       /*!< permutation table */
    }
    mbedtls_arc4_context;

    void mbedtls_arc4_setup(mbedtls_arc4_context* ctx, const unsigned char* key,
        unsigned int keylen);

    int mbedtls_arc4_crypt(mbedtls_arc4_context* ctx, size_t length, const unsigned char* input,
        unsigned char* output);
}