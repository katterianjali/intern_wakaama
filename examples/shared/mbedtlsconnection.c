#include "dtlsconnection.h"
#if defined LWM2M_CLIENT_MODE && defined DTLS
#include "liblwm2m.h"
#include "lwm2mclient.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/ssl.h"
#include "mbedtls/timing.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls_random.h"
#include "object_utils.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sec_context.h"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

typedef struct _dtlsconnection_t {
    connection_t conn;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_timing_delay_context timer;
    uint8_t *recvBuffer;
    size_t len;
} dtlsconnection_t;

static void dtlsconnection_deinit(void *conn) {
    dtlsconnection_t *dtlsConn = (dtlsconnection_t *)conn;

    int ret;

    /* No error checking, the connection might be closed already */
    do ret = mbedtls_ssl_close_notify( &dtlsConn->ssl );
    while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );
    
    mbedtls_ssl_config_free(&dtlsConn->conf);
    mbedtls_ctr_drbg_free(&dtlsConn->ctr_drbg);
    mbedtls_entropy_free(&dtlsConn->entropy);
    mbedtls_ssl_free(&dtlsConn->ssl);
}


#if defined(MBEDTLS_DEBUG_C)
static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}
#endif /* MBEDTLS_DEBUG_C */


#if defined(MBEDTLS_X509_CRT_PARSE_C)
static unsigned char peer_crt_info[1024];

/*
 * Enabled if debug_level > 1 in code below
 */
static int my_verify( void *data, mbedtls_x509_crt *crt,
                      int depth, uint32_t *flags )
{
    char buf[1024];
    ((void) data);

    //mbedtls_printf( "\nVerify requested for (Depth %d):\n", depth );

#if !defined(MBEDTLS_X509_REMOVE_INFO)
    mbedtls_x509_crt_info( buf, sizeof( buf ) - 1, "", crt );
    if( depth == 0 )
        memcpy( peer_crt_info, buf, sizeof( buf ) );

    //mbedtls_printf( "%s", buf );
#else
    ((void) crt);
    ((void) depth);
#endif

    if ( ( *flags ) != 0 )
    {
        mbedtls_x509_crt_verify_info( buf, sizeof( buf ), "  ! ", *flags );
        //mbedtls_printf( "%s\n", buf );
    }

    return( 0 );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */


static int dtlsconnection_recv(lwm2m_context_t *context, uint8_t *buffer, size_t len, void *conn) {
    dtlsconnection_t *dtlsConn = (dtlsconnection_t *)conn;
    int ret = 0;
    dtlsConn->recvBuffer = buffer;
    dtlsConn->len = len;

    do {
        ret = mbedtls_ssl_read(&dtlsConn->ssl, buffer, len);
    } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret < 0) {
#if defined(MBEDTLS_ERROR_C)
        char error_buf[200];
        mbedtls_strerror(ret, error_buf, 200);
        printf("Last error was: -0x%04x - %s\n\n", (unsigned int)-ret, error_buf);
#else
        printf("Last error was: -0x%04x\n\n", (unsigned int)-ret);
#endif /* MBEDTLS_ERROR_C */
    }

    if (ret > 0) {
        lwm2m_handle_packet(context, buffer, ret, dtlsConn);
        return ret;
    }
    return 0;
}

static int dtlsconnection_send(uint8_t const *buffer, size_t len, void *conn) {
    dtlsconnection_t *dtlsConn = (dtlsconnection_t *)conn;
    int ret = 0;
    do {
        ret = mbedtls_ssl_write(&dtlsConn->ssl, buffer, len);
    } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret < 0) {
#if defined(MBEDTLS_ERROR_C)
        char error_buf[200];
        mbedtls_strerror(ret, error_buf, 200);
        printf("Last error was: -0x%04x - %s\n\n", (unsigned int)-ret, error_buf);
#else
        printf("Last error was: -0x%04x\n\n", (unsigned int)-ret);
#endif /* MBEDTLS_ERROR_C */
    }
    return ret;
}

static int dtlsconnection_mbedtls_send(void *ctx, uint8_t const *buffer, size_t length) {
    dtlsconnection_t *connP = (dtlsconnection_t *)ctx;
    int nbSent;
    size_t offset;
    offset = 0;
    while (offset != length) {
        nbSent = sendto(connP->conn.sock, buffer + offset, length - offset, 0, (struct sockaddr *)&(connP->conn.addr),
                        connP->conn.addrLen);
        if (nbSent == -1)
            return -1;
        offset += nbSent;
    }
    return length;
}

static int dtlsconnection_mbedtls_recv(void *ctx, uint8_t *buf, size_t len) {
    dtlsconnection_t *conn = (dtlsconnection_t *)ctx;
    size_t minLen = MIN(len, conn->len);
    if (conn->recvBuffer != NULL) {
        memcpy(buf, conn->recvBuffer, minLen);
        if (minLen < conn->len) {
            conn->recvBuffer = conn->recvBuffer + minLen;
            conn->len = conn->len - minLen;
        } else {
            conn->recvBuffer = NULL;
            conn->len = 0;
        }

        return minLen;
    }
    return MBEDTLS_ERR_SSL_WANT_READ;
}

connection_t *dtlsconnection_create(lwm2m_connection_layer_t *connLayerP, uint16_t securityInstance, int sock,
                                    char *host, char *port, int addressFamily, uint16_t securityMode, sec_context_t *clientData) 
{
 
    dtlsconnection_t *dtlsConn = NULL;
    lwm2m_context_t *ctx = connLayerP->ctx;
    int ret = 0;
#if defined(WITH_MBEDTLS) && defined(MBEDTLS_X509_CRT_PARSE_C)
    uint8_t *cacert = NULL;  /* CA certificate                           */
    size_t cacert_len;       /* CA certificate length                    */
    uint8_t *clicert = NULL; /* Client certificate                       */
    size_t clicert_len;      /* Client certificate length                */
    uint8_t *pkey = NULL;    /* Client secret key                        */
    size_t pkey_len;         /* Client secret key length                 */
    rng_context_t rng;
#endif /* WITH_MBEDTLS && MBEDTLS_X509_CRT_PARSE_C */

#if defined(WITH_MBEDTLS) && defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    uint8_t *sni = NULL;     /* SNI                                      */
#endif /* WITH_MBEDTLS && MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(WITH_TINYDTLS) || ( defined(WITH_MBEDTLS) && defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) )    
    uint8_t *identity = NULL;      /* PSK Identity                    */
    size_t identityLen = 0;        /* PSK Identity length             */
    uint8_t *psk = NULL;           /* PSK                             */
    size_t pskLen = 0;             /* PSK length                      */
#endif /* WITH_TINYDTLS || (WITH_MBEDTLS && MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) */

#if defined(WITH_MBEDTLS) && defined(MBEDTLS_X509_CRT_PARSE_C)
    /* Initialize the RNG and the session data */
    rng_init( &rng );
    ret = rng_seed( &rng, 0, ctx->endpointName );
    if( ret != 0 )
    {
        fprintf(stderr, " failed\n  !  rng_seed returned -0x%x\n\n",
                   (unsigned int) -ret );
        return NULL;
    }
#endif /* WITH_MBEDTLS && MBEDTLS_X509_CRT_PARSE_C */

    dtlsConn = (dtlsconnection_t *)lwm2m_malloc(sizeof(dtlsconnection_t));
    if (dtlsConn == NULL) {
        return NULL;
    }
    memset(dtlsConn, 0, sizeof(dtlsconnection_t));
    if (connection_create_inplace(&dtlsConn->conn, sock, host, port, addressFamily) <= 0) {
        lwm2m_free(dtlsConn);
        return NULL;
    }
    dtlsConn->conn.sendFunc = dtlsconnection_send;
    dtlsConn->conn.recvFunc = dtlsconnection_recv;
    dtlsConn->conn.deinitFunc = dtlsconnection_deinit;
    
    mbedtls_ssl_init(&dtlsConn->ssl);
    mbedtls_ssl_config_init(&dtlsConn->conf);
    mbedtls_ctr_drbg_init(&dtlsConn->ctr_drbg);
    mbedtls_entropy_init(&dtlsConn->entropy);
    if ((ret = mbedtls_ctr_drbg_seed( &dtlsConn->ctr_drbg, 
                                      mbedtls_entropy_func, 
                                      &dtlsConn->entropy,
                                      (const unsigned char*) ctx->endpointName,
                                      strlen(ctx->endpointName) 
                                    )) != 0) 
    {
        dtlsconnection_deinit(dtlsConn);
        lwm2m_free(dtlsConn);
        return NULL;
    }

    /* Retrieve PSK Identity and PSK from LwM2M Security Object */
#if defined(WITH_TINYDTLS) || ( defined(WITH_MBEDTLS) && defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) )
    if (securityMode == LWM2M_SECURITY_MODE_PRE_SHARED_KEY)
    {    
        ret = security_get_public_key(connLayerP->ctx, securityInstance, &identity, &identityLen);
        if (ret <= 0) {
            return NULL;
        }
        ret = security_get_secret_key(connLayerP->ctx, securityInstance, &psk, &pskLen);
        if (ret <= 0) {
            lwm2m_free(identity);
            return NULL;
        }
    }
#endif /* WITH_TINYDTLS || (WITH_MBEDTLS && MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) */

#if defined(WITH_MBEDTLS) && defined(MBEDTLS_X509_CRT_PARSE_C)
    if (securityMode == LWM2M_SECURITY_MODE_CERTIFICATE)
    {
        ret = security_get_public_key(connLayerP->ctx, securityInstance, &clicert, &clicert_len);
        if (ret <= 0) {
            return NULL;
        }
        ret = security_get_secret_key(connLayerP->ctx, securityInstance, &pkey, &pkey_len);
        if (ret <= 0) {
            lwm2m_free(clicert);
            return NULL;
        }
        ret = security_get_server_public_key(connLayerP->ctx, securityInstance, &cacert, &cacert_len);
        if (ret <= 0) {
            lwm2m_free(clicert);
            lwm2m_free(pkey);
            return NULL;
        }

        ret = security_get_sni(connLayerP->ctx, securityInstance, &sni);
        if (ret <= 0) {
            lwm2m_free(clicert);
            lwm2m_free(pkey);
            lwm2m_free(cacert);
            return NULL;
        }

        /* Release earlier-allocated buffers */
        if ( clientData->allocated_buffers == 1)
        {
            mbedtls_x509_crt_free( &clientData->mbedtls_cacert  );
            mbedtls_x509_crt_free( &clientData->mbedtls_clicert );
            mbedtls_pk_free( &clientData->mbedtls_pkey );
        } else {
            clientData->allocated_buffers = 1;
        }

        /* Initialize data structures for certificates and private key */
        mbedtls_x509_crt_init( &clientData->mbedtls_cacert );
        mbedtls_x509_crt_init( &clientData->mbedtls_clicert );
        mbedtls_pk_init( &clientData->mbedtls_pkey );

        /* Parse CA certificate */
        ret = mbedtls_x509_crt_parse( &clientData->mbedtls_cacert, cacert, cacert_len );
        if( ret < 0 )
        {
            fprintf(stderr, " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n",
                            (unsigned int) -ret );
            lwm2m_free(pkey);
            lwm2m_free(clicert);
            lwm2m_free(cacert);
            return NULL;
        }

        /* Parse Client certificate */
        ret = mbedtls_x509_crt_parse( &clientData->mbedtls_clicert, clicert, clicert_len );
        if( ret != 0 )
        {
            fprintf(stderr, " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n",
                            (unsigned int) -ret );
            lwm2m_free(pkey);
            lwm2m_free(clicert);
            lwm2m_free(cacert);
            return NULL;
        }

        /* Parse Client Secret key */
        ret = mbedtls_pk_parse_key( &clientData->mbedtls_pkey, 
                                    pkey, pkey_len,
                                    NULL, 0,
                                    rng_get, &rng );
        if( ret != 0 )
        {
            fprintf(stderr, " failed\n  !  mbedtls_pk_parse_key returned -0x%x\n\n",
                            (unsigned int) -ret );
            lwm2m_free(pkey);
            lwm2m_free(clicert);
            lwm2m_free(cacert);
            return NULL;
        }
    }
#endif /* WITH_MBEDTLS && MBEDTLS_X509_CRT_PARSE_C */
        
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if( options.key_opaque != 0 )
    {
        data.secContext->key_slot = 0;

        if( ( ret = mbedtls_pk_wrap_as_opaque( &pkey, &data.secContext->key_slot,
                                               PSA_ALG_ANY_HASH ) ) != 0 )
        {
            fprintf(stderr, " failed\n  !  "
                            "mbedtls_pk_wrap_as_opaque returned -0x%x\n\n", (unsigned int)  -ret );
            return -1;
        }
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    if ((ret = mbedtls_ssl_config_defaults(&dtlsConn->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        dtlsconnection_deinit(dtlsConn);
        lwm2m_free(dtlsConn);
        return NULL;
    }

    // Configure ciphersuite according to security mode
    if( clientData->force_ciphersuite[0] != 0 ) {
        mbedtls_ssl_conf_ciphersuites(&dtlsConn->conf, clientData->force_ciphersuite);
    }

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    if( clientData->cid_len > 0 )
    {
        ret = mbedtls_ssl_conf_cid( &dtlsConn->conf, clientData->cid_len,
                                    MBEDTLS_SSL_UNEXPECTED_CID_IGNORE );

        if( ret != 0 )
        {
            fprintf(stderr, " failed\n  ! mbedtls_ssl_conf_cid_len returned -%#04x\n\n",
                            (unsigned int) -ret );
            dtlsconnection_deinit(dtlsConn);
            lwm2m_free(dtlsConn);
            return NULL;
        }
    }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    if (securityMode == LWM2M_SECURITY_MODE_PRE_SHARED_KEY)
    {
        if((ret = mbedtls_ssl_conf_psk( &dtlsConn->conf,
                                        psk, psk_len,
                                        psk_identity, psk_identity_len)
                                      ) != 0)
        {
            dtlsconnection_deinit(dtlsConn);
            lwm2m_free(dtlsConn);
            return NULL;
        }
    }
    else 
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (securityMode == LWM2M_SECURITY_MODE_CERTIFICATE)
    {
        mbedtls_ssl_conf_ca_chain( &dtlsConn->conf, &clientData->mbedtls_cacert, NULL );

        if( ( ret = mbedtls_ssl_conf_own_cert( &dtlsConn->conf, &clientData->mbedtls_clicert, &clientData->mbedtls_pkey ) ) != 0 )
        {
            dtlsconnection_deinit(dtlsConn);
            lwm2m_free(dtlsConn);       
            return NULL;
        }

       /* For testing, disable authentication */
       // mbedtls_ssl_conf_authmode( &conn->conf, MBEDTLS_SSL_VERIFY_NONE );
    } else
#endif /* MBEDTLS_X509_CRT_PARSE_C */
    {
        // Cannot happen
        return(NULL);
    }

    mbedtls_ssl_conf_rng(&dtlsConn->conf, mbedtls_ctr_drbg_random, &dtlsConn->ctr_drbg);
    mbedtls_ssl_set_bio(&dtlsConn->ssl, dtlsConn, dtlsconnection_mbedtls_send, dtlsconnection_mbedtls_recv, NULL);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_ssl_conf_dbg( &dtlsConn->conf, my_debug, stdout );
#endif /* MBEDTLS_DEBUG_C */

    mbedtls_ssl_set_timer_cb(&dtlsConn->ssl, &dtlsConn->timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (securityMode == LWM2M_SECURITY_MODE_CERTIFICATE)
    {
        mbedtls_ssl_conf_verify( &dtlsConn->conf, my_verify, NULL );
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    if ((ret = mbedtls_ssl_setup(&dtlsConn->ssl, &dtlsConn->conf)) != 0) {
        dtlsconnection_deinit(dtlsConn);
        lwm2m_free(dtlsConn);
        return NULL;
    }

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    if (clientData->cid_len > 0)
    {
        if( ( ret = mbedtls_ssl_set_cid( &dtlsConn->ssl,
                                         (clientData->cid_len > 0) ? MBEDTLS_SSL_CID_ENABLED : MBEDTLS_SSL_CID_DISABLED,
                                         clientData->cid, 
                                         clientData->cid_len ) ) != 0 )
        {
            fprintf(stderr, " failed\n  ! mbedtls_ssl_set_cid returned %d\n\n", ret );
            dtlsconnection_deinit(dtlsConn);
            lwm2m_free(dtlsConn);
            return NULL;
        }
    }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */


#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (securityMode == LWM2M_SECURITY_MODE_CERTIFICATE)
    {
        if( ( ret = mbedtls_ssl_set_hostname( &dtlsConn->ssl, (const char *) sni ) ) != 0 )
        {
            dtlsconnection_deinit(dtlsConn);
            lwm2m_free(dtlsConn);
            return NULL;
        }
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */


#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (securityMode == LWM2M_SECURITY_MODE_CERTIFICATE)
    {
        mbedtls_ssl_set_verify( &dtlsConn->ssl, my_verify, NULL );
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    connectionlayer_add_connection(connLayerP, (connection_t *)dtlsConn);

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    // Release retrieved certificate data
//    lwm2m_free(pkey);
//    lwm2m_free(clicert);
//    lwm2m_free(cacert);
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    return (connection_t *)dtlsConn;
}

#else
connection_t *dtlsconnection_create(lwm2m_connection_layer_t *connLayerP, uint16_t securityInstance, int sock,
                                    char *host, char *port, int addressFamily) {
    (void)connLayerP;
    (void)securityInstance;
    (void)sock;
    (void)host;
    (void)port;
    (void)addressFamily;
    return NULL;
}
#endif /* LWM2M_CLIENT_MODE && DTLS */
