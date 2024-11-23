#include "arc4.h"

namespace ARC4 {
    void mbedtls_arc4_setup(mbedtls_arc4_context* ctx, const unsigned char* key,
        unsigned int keylen)
    {
        int i, j, a;
        unsigned int k;
        unsigned char* m;

        ctx->x = 0;
        ctx->y = 0;
        m = ctx->m;

        for (i = 0; i < 256; i++)
            m[i] = (unsigned char)i;

        j = k = 0;

        for (i = 0; i < 256; i++, k++)
        {
            if (k >= keylen) k = 0;

            a = m[i];
            j = (j + a + key[k]) & 0xFF;
            m[i] = m[j];
            m[j] = (unsigned char)a;
        }
    }

    int mbedtls_arc4_crypt(mbedtls_arc4_context* ctx, size_t length, const unsigned char* input,
        unsigned char* output)
    {
        int x, y, a, b;
        size_t i;
        unsigned char* m;

        x = ctx->x;
        y = ctx->y;
        m = ctx->m;

        for (i = 0; i < length; i++)
        {
            x = (x + 1) & 0xFF; a = m[x];
            y = (y + a) & 0xFF; b = m[y];

            m[x] = (unsigned char)b;
            m[y] = (unsigned char)a;

            output[i] = (unsigned char)
                (input[i] ^ m[(unsigned char)(a + b)]);
        }

        ctx->x = x;
        ctx->y = y;

        return(0);
    }
}