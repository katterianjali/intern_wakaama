#ifndef SECCONTEXT_H_
#define SECCONTEXT_H_

#include "liblwm2m.h"

#if defined WITH_MBEDTLS
#include "mbedtls/build_info.h"
#ifdef MBEDTLS_X509_CRT_PARSE_C
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls_random.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* WITH_MBEDTLS */


/*
 * global options
 */
#if defined WITH_TINYDTLS || defined WITH_MBEDTLS
/* Data structure to hold the parameters passed via the command line. */
typedef struct
{
#if defined(WITH_MBEDTLS) && defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_FS_IO)
    char *ca_file;                               /* the file with the CA certificate(s)      */
    char *crt_file;                              /* the file with the client certificate     */
    char *key_file;                              /* the file with the client key             */
#endif /* MBEDTLS_FS_IO */
    uint8_t *cacert;                             /* CA certificate                           */
    size_t cacert_len;                           /* CA certificate length                    */
    uint8_t *clicert;                            /* Client certificate                       */
    size_t clicert_len;                          /* Client certificate length                */
    uint8_t *pkey;                               /* Client secret key                        */
    size_t pkey_len;                             /* Client secret key length                 */
#endif  /* MBEDTLS_X509_CRT_PARSE_C */
    int key_opaque;                              /* handle private key as if it were opaque  */
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    mbedtls_svc_key_id_t key_slot;
#endif 
    int debug_level;                             /* level of debugging                       */
    int force_ciphersuite[2];                    /* protocol/ciphersuite to use, or all      */
#if defined(WITH_MBEDTLS) && defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt mbedtls_cacert;
    mbedtls_x509_crt mbedtls_clicert;
    mbedtls_pk_context mbedtls_pkey;
    uint32_t allocated_buffers;
#endif  /* MBEDTLS_X509_CRT_PARSE_C */
#if defined(WITH_MBEDTLS) && defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    uint8_t sni_len;                              /* Length of the SNI                        */
    char *sni;                                    /* SNI                                      */
#endif /* WITH_MBEDTLS && MBEDTLS_SSL_SERVER_NAME_INDICATION */
#if defined(WITH_MBEDTLS) && defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    unsigned char cid[MBEDTLS_SSL_CID_IN_LEN_MAX];/* the CID to use for incoming messages     */
    size_t cid_len;
    int cid_enabled;                             /* whether to use the CID extension or not   */
#endif /* WITH_MBEDTLS && MBEDTLS_SSL_DTLS_CONNECTION_ID */
    uint8_t *psk_identity;                        /* PSK identity                             */
    size_t psk_identity_len;                      /* PSK identity length                      */
    uint8_t *psk;                                 /* the pre-shared key input                 */
    size_t psk_len;                               /* the psk length                           */    
} sec_context_t;
#endif /* WITH_TINYDTLS || WITH_MBEDTLS */

#if defined(WITH_MBEDTLS) && defined(MBEDTLS_X509_CRT_PARSE_C)
void rng_init( rng_context_t *rng );
int rng_seed( rng_context_t *rng, int reproducible, const char *pers );
void rng_free( rng_context_t *rng );
int rng_get( void *p_rng, unsigned char *output, size_t output_len );
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#endif /* SECCONTEXT_H_ */
