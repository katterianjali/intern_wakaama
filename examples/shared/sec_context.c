#include "sec_context.h"


#if defined(WITH_MBEDTLS) && defined(MBEDTLS_X509_CRT_PARSE_C)

#if !defined(MBEDTLS_TEST_USE_PSA_CRYPTO_RNG)
static int dummy_entropy( void *data, unsigned char *output, size_t len )
{
    size_t i;
    int ret;
    (void) data;

    ret = mbedtls_entropy_func( data, output, len );
    for( i = 0; i < len; i++ )
    {
        //replace result with pseudo random
        output[i] = (unsigned char) rand();
    }
    return( ret );
}
#endif

void rng_init( rng_context_t *rng )
{
#if defined(MBEDTLS_TEST_USE_PSA_CRYPTO_RNG)
    (void) rng;
    psa_crypto_init( );
#else /* !MBEDTLS_TEST_USE_PSA_CRYPTO_RNG */

#if defined(MBEDTLS_CTR_DRBG_C)
    mbedtls_ctr_drbg_init( &rng->drbg );
#elif defined(MBEDTLS_HMAC_DRBG_C)
    mbedtls_hmac_drbg_init( &rng->drbg );
#else
#error "No DRBG available"
#endif

    mbedtls_entropy_init( &rng->entropy );
#endif /* !MBEDTLS_TEST_USE_PSA_CRYPTO_RNG */
}

int rng_seed( rng_context_t *rng, int reproducible, const char *pers )
{
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if( reproducible )
    {
        fprintf( stderr,
                 "MBEDTLS_USE_PSA_CRYPTO does not support reproducible mode.\n" );
        return( -1 );
    }
#endif
#if defined(MBEDTLS_TEST_USE_PSA_CRYPTO_RNG)
    /* The PSA crypto RNG does its own seeding. */
    (void) rng;
    (void) pers;
    if( reproducible )
    {
        fprintf( stderr,
                 "The PSA RNG does not support reproducible mode.\n" );
        return( -1 );
    }
    return( 0 );
#else /* !MBEDTLS_TEST_USE_PSA_CRYPTO_RNG */
    int ( *f_entropy )( void *, unsigned char *, size_t ) =
        ( reproducible ? dummy_entropy : mbedtls_entropy_func );

    if ( reproducible )
        srand( 1 );

#if defined(MBEDTLS_CTR_DRBG_C)
    int ret = mbedtls_ctr_drbg_seed( &rng->drbg,
                                     f_entropy, &rng->entropy,
                                     (const unsigned char *) pers,
                                     strlen( pers ) );
#elif defined(MBEDTLS_HMAC_DRBG_C)
#if defined(MBEDTLS_SHA256_C)
    const mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
#elif defined(MBEDTLS_SHA512_C)
    const mbedtls_md_type_t md_type = MBEDTLS_MD_SHA512;
#else
#error "No message digest available for HMAC_DRBG"
#endif
    int ret = mbedtls_hmac_drbg_seed( &rng->drbg,
                                      mbedtls_md_info_from_type( md_type ),
                                      f_entropy, &rng->entropy,
                                      (const unsigned char *) pers,
                                      strlen( pers ) );
#else /* !defined(MBEDTLS_CTR_DRBG_C) && !defined(MBEDTLS_HMAC_DRBG_C) */
#error "No DRBG available"
#endif /* !defined(MBEDTLS_CTR_DRBG_C) && !defined(MBEDTLS_HMAC_DRBG_C) */

    if( ret != 0 )
    {
        fprintf(stdout, " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%x\n",
                        (unsigned int) -ret );
        return( ret );
    }
#endif /* !MBEDTLS_TEST_USE_PSA_CRYPTO_RNG */

    return( 0 );
}

void rng_free( rng_context_t *rng )
{
#if defined(MBEDTLS_TEST_USE_PSA_CRYPTO_RNG)
    (void) rng;
    /* Deinitialize the PSA crypto subsystem. This deactivates all PSA APIs.
     * This is ok because none of our applications try to do any crypto after
     * deinitializing the RNG. */
    mbedtls_psa_crypto_free( );
#else /* !MBEDTLS_TEST_USE_PSA_CRYPTO_RNG */

#if defined(MBEDTLS_CTR_DRBG_C)
    mbedtls_ctr_drbg_free( &rng->drbg );
#elif defined(MBEDTLS_HMAC_DRBG_C)
    mbedtls_hmac_drbg_free( &rng->drbg );
#else
#error "No DRBG available"
#endif

    mbedtls_entropy_free( &rng->entropy );
#endif /* !MBEDTLS_TEST_USE_PSA_CRYPTO_RNG */
}

int rng_get( void *p_rng, unsigned char *output, size_t output_len )
{
#if defined(MBEDTLS_TEST_USE_PSA_CRYPTO_RNG)
    (void) p_rng;
    return( mbedtls_psa_get_random( MBEDTLS_PSA_RANDOM_STATE,
                                    output, output_len ) );
#else /* !MBEDTLS_TEST_USE_PSA_CRYPTO_RNG */
    rng_context_t *rng = p_rng;

#if defined(MBEDTLS_CTR_DRBG_C)
    return( mbedtls_ctr_drbg_random( &rng->drbg, output, output_len ) );
#elif defined(MBEDTLS_HMAC_DRBG_C)
    return( mbedtls_hmac_drbg_random( &rng->drbg, output, output_len ) );
#else
#error "No DRBG available"
#endif

#endif /* !MBEDTLS_TEST_USE_PSA_CRYPTO_RNG */
}
#endif /* WITH_MBEDTLS && MBEDTLS_X509_CRT_PARSE_C */
