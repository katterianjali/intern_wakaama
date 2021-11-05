#ifdef LWM2M_CLIENT_MODE
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <stdint.h>
#include <string.h>
#include "liblwm2m.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"
#include "mbedtls/error.h"
#include "lwm2mclient.h"
#include "mbedtlsconnection.h"
#include <stdio.h>
#define COAP_PORT "5683"
#define COAPS_PORT "5684"


typedef struct {
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_timing_delay_context timer;
}dtlsconnection_t;



char * lwm2m_get_uri(lwm2m_context_t * lwm2mH, lwm2m_object_t * obj, int instanceId){
    int size = 1;
    lwm2m_data_t * dataP = lwm2m_data_new(size);
    if(dataP == NULL) return NULL;
    dataP->id = LWM2M_SECURITY_URI_ID; // security server uri

    uint8_t ret = obj->readFunc(lwm2mH, instanceId, &size, &dataP, obj);
    char * uri = NULL;
    if (ret == COAP_205_CONTENT && dataP->type == LWM2M_TYPE_STRING && dataP->value.asBuffer.length > 0)
    {
        uri = (char*)lwm2m_malloc(dataP->value.asBuffer.length + 1);
        if(uri != NULL) {
            memset(uri,0,dataP->value.asBuffer.length+1);
            memcpy(uri,dataP->value.asBuffer.buffer, dataP->value.asBuffer.length);
        }
    }
    lwm2m_data_free(size, dataP);
    return uri;
}

uint8_t lwm2m_get_securityMode(lwm2m_context_t * lwm2mH, lwm2m_object_t * obj, int instanceId){
    int size = 1;
    lwm2m_data_t * dataP = lwm2m_data_new(size);
    if(dataP == NULL) return -1;
    dataP->id = LWM2M_SECURITY_SECURITY_MODE_ID; // security mode

    uint8_t ret = obj->readFunc(lwm2mH, instanceId, &size, &dataP, obj);
    uint8_t securityMode = -1;

    if (ret == COAP_205_CONTENT && dataP->type == LWM2M_TYPE_INTEGER && dataP->value.asInteger >= 0)
    {
        securityMode = (uint8_t) dataP->value.asInteger;
    }
    lwm2m_data_free(size, dataP);
    return securityMode;
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


void * lwm2m_connect_server(uint16_t secObjInstID, void * userData)
{
    client_data_t * client_data = (client_data_t*)userData;

    char * host;
    char * port;
    char * uri = lwm2m_get_uri(client_data->ctx, client_data->securityObjP, secObjInstID);
    if(uri == NULL) return NULL;

    char * defaultport;
    if (0 == strncmp(uri, "coaps://", strlen("coaps://")))
    {
        host = uri+strlen("coaps://");
        defaultport = COAPS_PORT;
    }
    else if (0 == strncmp(uri, "coap://", strlen("coap://")))
    {
        host = uri+strlen("coap://");
        defaultport = COAP_PORT;
    }
    else
    {
        lwm2m_free(uri);
        return NULL;
    }
    port = strrchr(host, ':');
    if (port == NULL)
    {
        port = defaultport;
    }
    else
    {
        // remove brackets
        if (host[0] == '[')
        {
            host++;
            if (*(port - 1) == ']')
            {
                *(port - 1) = 0;
            }
            else
            {
                lwm2m_free(uri);
                return NULL;
            }
        }
        // split strings
        *port = 0;
        port++;
    }

    uint8_t securityMode;
    
    securityMode=lwm2m_get_securityMode(client_data->ctx, client_data->securityObjP, secObjInstID);

    if (securityMode != LWM2M_SECURITY_MODE_PRE_SHARED_KEY && securityMode != LWM2M_SECURITY_MODE_CERTIFICATE)
    {
        // Unsupported security mode
        lwm2m_free(uri);
        return NULL;
    }

    dtlsconnection_t * conn = (dtlsconnection_t*)lwm2m_malloc(sizeof(dtlsconnection_t));
    int ret = 0;
    if (conn == NULL) {
        lwm2m_free(uri);
        return NULL;
    }

    mbedtls_net_init(&conn->server_fd );
    mbedtls_ssl_init(&conn->ssl);
    mbedtls_ssl_config_init(&conn->conf);
    mbedtls_ctr_drbg_init(&conn->ctr_drbg);
    mbedtls_entropy_init(&conn->entropy);
                           
    if((ret = mbedtls_ctr_drbg_seed( &conn->ctr_drbg, 
                                     mbedtls_entropy_func, 
                                     &conn->entropy,
                                     (const unsigned char*) client_data->ctx->endpointName,
                                     strlen(client_data->ctx->endpointName)
                                    )) != 0) 
    {
        mbedtls_net_free(&conn->server_fd);
        mbedtls_ssl_config_free(&conn->conf);
        mbedtls_ctr_drbg_free(&conn->ctr_drbg);
        mbedtls_entropy_free(&conn->entropy);
        mbedtls_ssl_free(&conn->ssl);
        lwm2m_free(uri);
        lwm2m_free(conn);
        return NULL;
    }

    if((ret = mbedtls_net_connect(&conn->server_fd, host, port, MBEDTLS_NET_PROTO_UDP)) != 0)
    {
        mbedtls_net_free(&conn->server_fd);
        mbedtls_ssl_config_free(&conn->conf);
        mbedtls_ctr_drbg_free(&conn->ctr_drbg);
        mbedtls_entropy_free(&conn->entropy);
        mbedtls_ssl_free(&conn->ssl);
        lwm2m_free(uri);
        lwm2m_free(conn);
        return NULL;
    }

    if((ret = mbedtls_ssl_config_defaults(&conn->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) 
    {
        mbedtls_net_free(&conn->server_fd);
        mbedtls_ssl_config_free(&conn->conf);
        mbedtls_ctr_drbg_free(&conn->ctr_drbg);
        mbedtls_entropy_free(&conn->entropy);
        mbedtls_ssl_free(&conn->ssl);
        lwm2m_free(uri);
        lwm2m_free(conn);
        return NULL;
    }

    // Configure ciphersuite according to security mode
    if( client_data->force_ciphersuite[0] != 0 ) {
        mbedtls_ssl_conf_ciphersuites(&conn->conf, client_data->force_ciphersuite);
    }


#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    if( client_data->cid_len > 0 )
    {
        ret = mbedtls_ssl_conf_cid( &conn->conf, client_data->cid_len,
                                    MBEDTLS_SSL_UNEXPECTED_CID_IGNORE );

        if( ret != 0 )
        {
            fprintf(stderr, " failed\n  ! mbedtls_ssl_conf_cid_len returned -%#04x\n\n",
                            (unsigned int) -ret );
            mbedtls_net_free(&conn->server_fd);
            mbedtls_ssl_config_free(&conn->conf);
            mbedtls_ctr_drbg_free(&conn->ctr_drbg);
            mbedtls_entropy_free(&conn->entropy);
            mbedtls_ssl_free(&conn->ssl);
            lwm2m_free(uri);
            lwm2m_free(conn);
            return NULL;
        }
    }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */


#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    if (securityMode == LWM2M_SECURITY_MODE_PRE_SHARED_KEY)
    {
        if((ret = mbedtls_ssl_conf_psk( &conn->conf, 
                                        client_data->psk, client_data->psk_len,
                                        client_data->psk_identity, client_data->psk_identity_len)
                                      ) != 0) 
        {
            mbedtls_net_free(&conn->server_fd);
            mbedtls_ssl_config_free(&conn->conf);
            mbedtls_ctr_drbg_free(&conn->ctr_drbg);
            mbedtls_entropy_free(&conn->entropy);
            mbedtls_ssl_free(&conn->ssl);
            lwm2m_free(uri);
            lwm2m_free(conn);
            return NULL;
        }
    }
    else 
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (securityMode == LWM2M_SECURITY_MODE_CERTIFICATE)
    {
        mbedtls_ssl_conf_ca_chain( &conn->conf, client_data->cacert, NULL );

        if( ( ret = mbedtls_ssl_conf_own_cert( &conn->conf, client_data->clicert, client_data->pkey ) ) != 0 )
        {
            mbedtls_net_free(&conn->server_fd);
            mbedtls_ssl_config_free(&conn->conf);
            mbedtls_ctr_drbg_free(&conn->ctr_drbg);
            mbedtls_entropy_free(&conn->entropy);
            mbedtls_ssl_free(&conn->ssl);
            lwm2m_free(uri);
            lwm2m_free(conn);            
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

    mbedtls_ssl_conf_rng(&conn->conf, mbedtls_ctr_drbg_random, &conn->ctr_drbg);
    mbedtls_ssl_set_bio(&conn->ssl, &conn->server_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);
    // void mbedtls_ssl_conf_read_timeout( mbedtls_ssl_config *conf, uint32_t timeout ); //timeout millseconds

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_ssl_conf_dbg( &conn->conf, my_debug, stdout );
#endif /* MBEDTLS_DEBUG_C */

    mbedtls_ssl_set_timer_cb(&conn->ssl, &conn->timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (securityMode == LWM2M_SECURITY_MODE_CERTIFICATE)
    {
        mbedtls_ssl_conf_verify( &conn->conf, my_verify, NULL );
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    if((ret = mbedtls_ssl_setup(&conn->ssl, &conn->conf)) != 0)
    {
        mbedtls_net_free(&conn->server_fd);
        mbedtls_ssl_config_free(&conn->conf);
        mbedtls_ctr_drbg_free(&conn->ctr_drbg);
        mbedtls_entropy_free(&conn->entropy);
        mbedtls_ssl_free(&conn->ssl);
        lwm2m_free(uri);
        lwm2m_free(conn);
        return NULL;
    }


#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    if (client_data->cid_len > 0)
    {
        if( ( ret = mbedtls_ssl_set_cid( &conn->ssl,
                                         (client_data->cid_len > 0) ? MBEDTLS_SSL_CID_ENABLED : MBEDTLS_SSL_CID_DISABLED,
                                         client_data->cid, 
                                         client_data->cid_len ) ) != 0 )
        {
            fprintf(stderr, " failed\n  ! mbedtls_ssl_set_cid returned %d\n\n",
                            ret );
            mbedtls_net_free(&conn->server_fd);
            mbedtls_ssl_config_free(&conn->conf);
            mbedtls_ctr_drbg_free(&conn->ctr_drbg);
            mbedtls_entropy_free(&conn->entropy);
            mbedtls_ssl_free(&conn->ssl);
            lwm2m_free(uri);
            lwm2m_free(conn);
            return NULL;
        }
    }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */


#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (securityMode == LWM2M_SECURITY_MODE_CERTIFICATE)
    {

        if( ( ret = mbedtls_ssl_set_hostname( &conn->ssl, host ) ) != 0 )
        {
            mbedtls_net_free(&conn->server_fd);
            mbedtls_ssl_config_free(&conn->conf);
            mbedtls_ctr_drbg_free(&conn->ctr_drbg);
            mbedtls_entropy_free(&conn->entropy);
            mbedtls_ssl_free(&conn->ssl);
            lwm2m_free(uri);
            lwm2m_free(conn);
            return NULL;
        }
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */


#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (securityMode == LWM2M_SECURITY_MODE_CERTIFICATE)
    {
        mbedtls_ssl_set_verify( &conn->ssl, my_verify, NULL );
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    lwm2m_free(uri);

    return conn;
}

void lwm2m_close_connection(void * sessionH, void * userData)
{
    dtlsconnection_t * conn = (dtlsconnection_t*)sessionH;
    mbedtls_net_free(&conn->server_fd);
    mbedtls_ssl_config_free(&conn->conf);
    mbedtls_ctr_drbg_free(&conn->ctr_drbg);
    mbedtls_entropy_free(&conn->entropy);
    mbedtls_ssl_free(&conn->ssl);
}

uint8_t lwm2m_buffer_send(void * sessionH,
                          uint8_t * buffer,
                          size_t length,
                          void * userdata)
{
    int ret = 0;
    dtlsconnection_t * conn = (dtlsconnection_t*)sessionH;
    do {
        ret = mbedtls_ssl_write(&conn->ssl, buffer, length);
    }while(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if(ret < 0) {
#if defined(MBEDTLS_ERROR_C)
        char error_buf[200];
        mbedtls_strerror( ret, error_buf, 200 );
        printf("Last error was: -0x%04x - %s\n\n", (unsigned int) -ret, error_buf );
#else 
        printf("Last error was: -0x%04x\n\n", (unsigned int) -ret );
#endif /* MBEDTLS_ERROR_C */
     
    }

    return COAP_NO_ERROR;
}

bool lwm2m_session_is_equal(void * session1,
                            void * session2,
                            void * userdata)
{
    (void)userdata;
    return (session1 == session2);
}

int * mbedtls_get_sockets(lwm2m_context_t const * ctx, int * cnt) {
    int * socks = NULL;
    *cnt = 0;
    lwm2m_server_t * serv = ctx->serverList;
    while(serv != NULL) {
        if(serv->sessionH != NULL) {
            dtlsconnection_t * conn = (dtlsconnection_t *)serv->sessionH;
            if(conn->server_fd.fd > 0) {
                int * newSocks = lwm2m_malloc(sizeof(int)*((*cnt) + 1));
                memcpy(newSocks, socks, *cnt);
                newSocks[*cnt] = conn->server_fd.fd;
                lwm2m_free(socks);
                socks = newSocks;
                (*cnt)++;
            }
        }

        serv = serv->next;
    }
    return socks;
}

int mbedtls_receive(lwm2m_context_t const * ctx, int sock, uint8_t * buffer, int sz, void ** connection) {
    lwm2m_server_t * serv = ctx->serverList;
    dtlsconnection_t * conn = NULL;
    while(serv != NULL && conn == NULL) {
        if(serv->sessionH != NULL) {
            conn = (dtlsconnection_t *)serv->sessionH;
            if(conn->server_fd.fd != sock) {
                conn = NULL;
            }
        }

        serv = serv->next;
    }
    if(conn == NULL) {
        return 0;
    }
    int ret = 0;
    do {
        ret = mbedtls_ssl_read(&conn->ssl, buffer, sz);
    } while(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    *connection = conn;
    return ret;
}

#endif /* LWM2M_CLIENT_MODE */

