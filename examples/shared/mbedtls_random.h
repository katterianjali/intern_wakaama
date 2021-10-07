

#ifndef MBEDTLS_RANDOM_LIB_H
#define MBEDTLS_RANDOM_LIB_H

#include "mbedtls/build_info.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <stddef.h>

/** A context for random number generation (RNG).
 */
typedef struct
{
#if defined(MBEDTLS_TEST_USE_PSA_CRYPTO_RNG)
    unsigned char dummy;
#else /* MBEDTLS_TEST_USE_PSA_CRYPTO_RNG */
    mbedtls_entropy_context entropy;
#if defined(MBEDTLS_CTR_DRBG_C)
    mbedtls_ctr_drbg_context drbg;
#elif defined(MBEDTLS_HMAC_DRBG_C)
    mbedtls_hmac_drbg_context drbg;
#else
#error "No DRBG available"
#endif
#endif /* MBEDTLS_TEST_USE_PSA_CRYPTO_RNG */
} rng_context_t;

/** Initialize the RNG.
 *
 * This function only initializes the memory used by the RNG context.
 * Before using the RNG, it must be seeded with rng_seed().
 */
void rng_init( rng_context_t *rng );

/* Seed the random number generator.
 *
 * \param rng           The RNG context to use. It must have been initialized
 *                      with rng_init().
 * \param reproducible  If zero, seed the RNG from entropy.
 *                      If nonzero, use a fixed seed, so that the program
 *                      will produce the same sequence of random numbers
 *                      each time it is invoked.
 * \param pers          A null-terminated string. Different values for this
 *                      string cause the RNG to emit different output for
 *                      the same seed.
 *
 * return 0 on success, a negative value on error.
 */
int rng_seed( rng_context_t *rng, int reproducible, const char *pers );

/** Deinitialize the RNG. Free any embedded resource.
 *
 * \param rng           The RNG context to deinitialize. It must have been
 *                      initialized with rng_init().
 */
void rng_free( rng_context_t *rng );

/** Generate random data.
 *
 * This function is suitable for use as the \c f_rng argument to Mbed TLS
 * library functions.
 *
 * \param p_rng         The random generator context. This must be a pointer to
 *                      a #rng_context_t structure.
 * \param output        The buffer to fill.
 * \param output_len    The length of the buffer in bytes.
 *
 * \return              \c 0 on success.
 * \return              An Mbed TLS error code on error.
 */
int rng_get( void *p_rng, unsigned char *output, size_t output_len );

#endif /* MBEDTLS_RANDOM_LIB_H */
