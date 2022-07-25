/*******************************************************************************
 *
 * Copyright (c) 2013, 2014 Intel Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * The Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    David Navarro, Intel Corporation - initial API and implementation
 *    Benjamin Cabé - Please refer to git log
 *    Fabien Fleutot - Please refer to git log
 *    Simon Bernard - Please refer to git log
 *    Julien Vermillard - Please refer to git log
 *    Axel Lorente - Please refer to git log
 *    Toby Jaffey - Please refer to git log
 *    Bosch Software Innovations GmbH - Please refer to git log
 *    Pascal Rieux - Please refer to git log
 *    Christian Renz - Please refer to git log
 *    Ricky Liu - Please refer to git log
 *
 *******************************************************************************/

/*
 Copyright (c) 2013, 2014 Intel Corporation

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.
     * Neither the name of Intel Corporation nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 THE POSSIBILITY OF SUCH DAMAGE.

 David Navarro <david.navarro@intel.com>
 Bosch Software Innovations GmbH - Please refer to git log

*/

#include "lwm2mclient.h"
#include "liblwm2m.h"
#include "commandline.h"

#if defined(DTLS)
#include "dtlsconnection.h"
#endif

#include "connection.h"
#include "object_utils.h"

#if defined(WITH_MBEDTLS)
#include "mbedtls/build_info.h"
#include "mbedtls/build_info.h"
#include "mbedtls/debug.h"
#ifdef MBEDTLS_X509_CRT_PARSE_C
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls_random.h"
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* WITH_MBEDTLS */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#include "mbedtls/psa_util.h"
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#define MAX_PACKET_SIZE 2048
#define DEFAULT_SERVER_IPV6 "[::1]"
#define DEFAULT_SERVER_IPV4 "127.0.0.1"

int g_reboot = 0;
static int g_quit = 0;

#define OBJ_COUNT 10
lwm2m_object_t * objArray[OBJ_COUNT];


// only backup security and server objects
# define BACKUP_OBJECT_COUNT 2
lwm2m_object_t * backupObjectArray[BACKUP_OBJECT_COUNT];

static void prv_quit(lwm2m_context_t * lwm2mH,
                     char * buffer,
                     void * user_data)
{
    /* unused parameters */
    (void)lwm2mH;
    (void)buffer;
    (void)user_data;

    g_quit = 1;
}

void handle_sigint(int signum)
{
    g_quit = 2;
}

void handle_value_changed(lwm2m_context_t * lwm2mH,
                          lwm2m_uri_t * uri,
                          const char * value,
                          size_t valueLength)
{
    lwm2m_object_t * object = (lwm2m_object_t *)LWM2M_LIST_FIND(lwm2mH->objectList, uri->objectId);

    if (NULL != object)
    {
        if (object->writeFunc != NULL)
        {
            lwm2m_data_t * dataP;
            int result;

            dataP = lwm2m_data_new(1);
            if (dataP == NULL)
            {
                fprintf(stderr, "Internal allocation failure !\n");
                return;
            }
            dataP->id = uri->resourceId;

#ifndef LWM2M_VERSION_1_0
            if (LWM2M_URI_IS_SET_RESOURCE_INSTANCE(uri))
            {
                lwm2m_data_t *subDataP = lwm2m_data_new(1);
                if (subDataP == NULL)
                {
                    fprintf(stderr, "Internal allocation failure !\n");
                    lwm2m_data_free(1, dataP);
                    return;
                }
                subDataP->id = uri->resourceInstanceId;
                lwm2m_data_encode_nstring(value, valueLength, subDataP);
                lwm2m_data_encode_instances(subDataP, 1, dataP);
            }
            else
#endif /* LWM2M_VERSION_1_0 */
            {
                lwm2m_data_encode_nstring(value, valueLength, dataP);
            }

            result = object->writeFunc(lwm2mH, uri->instanceId, 1, dataP, object, LWM2M_WRITE_PARTIAL_UPDATE);
            if (COAP_405_METHOD_NOT_ALLOWED == result)
            {
                switch (uri->objectId)
                {
                case LWM2M_DEVICE_OBJECT_ID:
                    result = device_change(dataP, object);
                    break;
                default:
                    break;
                }
            }

            if (COAP_204_CHANGED != result)
            {
                fprintf(stderr, "Failed to change value!\n");
            }
            else
            {
                fprintf(stderr, "value changed!\n");
                lwm2m_resource_value_changed(lwm2mH, uri);
            }
            lwm2m_data_free(1, dataP);
            return;
        }
        else
        {
            fprintf(stderr, "write not supported for specified resource!\n");
        }
        return;
    }
    else
    {
        fprintf(stderr, "Object not found !\n");
    }
}

int print_bytestr(const uint8_t *bytes, size_t len)
{
    if (bytes == NULL)
        return( -1 );

    for(unsigned int idx=0; idx < len; idx++)
    {
        fprintf(stderr, "%02x", bytes[idx]);
    }
    return( 0 );
}



void *lwm2m_connect_server(uint16_t secObjInstID, void *userData) {
    int securityMode = 0;
    int ret = 0;
    client_data_t *dataP;
    char *uri;
    char *host;
    char *port;
    connection_t *newConnP = NULL;

    dataP = (client_data_t *)userData;

    uri = get_server_uri(dataP->securityObjP, secObjInstID);

    if (uri == NULL) return NULL;

    // parse uri in the form "coaps://[host]:[port]"
    if (0==strncmp(uri, "coaps://", strlen("coaps://"))) {
        host = uri+strlen("coaps://");
    }
    else if (0==strncmp(uri, "coap://",  strlen("coap://"))) {
        host = uri+strlen("coap://");
    }
    else {
        goto exit;
    }
    port = strrchr(host, ':');
    if (port == NULL) goto exit;
    // remove brackets
    if (host[0] == '[')
    {
        host++;
        if (*(port - 1) == ']')
        {
            *(port - 1) = 0;
        }
        else goto exit;
    }
    // split strings
    *port = 0;
    port++;

    fprintf(stderr, "Opening connection to server at %s:%s\r\n", host, port);
    ret = security_get_security_mode(dataP->ctx, secObjInstID, &securityMode);
    if (ret <= 0) {
        goto exit;
    }
    if (securityMode == LWM2M_SECURITY_MODE_PRE_SHARED_KEY || securityMode == LWM2M_SECURITY_MODE_CERTIFICATE) {
#if defined(DTLS)
        newConnP = (connection_t *)dtlsconnection_create(dataP->connLayer, secObjInstID, dataP->sock, host, port,
                                                         dataP->addressFamily, securityMode, dataP->secContext);
#endif
    } else if (securityMode == LWM2M_SECURITY_MODE_NONE) {
        newConnP = connection_create(dataP->connLayer, dataP->sock, host, port, dataP->addressFamily);
    }

    if (newConnP == NULL) {
        fprintf(stderr, "Connection creation failed.\r\n");
    }

exit:
    lwm2m_free(uri);
    return (void *)newConnP;
}

void lwm2m_close_connection(void *sessionH, void *userData) {
    client_data_t *app_data;
    connection_t *targetP;

    app_data = (client_data_t *)userData;
    targetP = (connection_t *)sessionH;
    connectionlayer_free_connection(app_data->connLayer, targetP);
}

static void prv_output_servers(lwm2m_context_t * lwm2mH,
                               char * buffer,
                               void * user_data)
{
    lwm2m_server_t * targetP;

    /* unused parameter */
    (void)user_data;

    targetP = lwm2mH->bootstrapServerList;

    if (lwm2mH->bootstrapServerList == NULL)
    {
        fprintf(stdout, "No Bootstrap Server.\r\n");
    }
    else
    {
        fprintf(stdout, "Bootstrap Servers:\r\n");
        for (targetP = lwm2mH->bootstrapServerList ; targetP != NULL ; targetP = targetP->next)
        {
            fprintf(stdout, " - Security Object ID %d", targetP->secObjInstID);
            fprintf(stdout, "\tHold Off Time: %lu s", (unsigned long)targetP->lifetime);
            fprintf(stdout, "\tstatus: ");
            switch(targetP->status)
            {
            case STATE_DEREGISTERED:
                fprintf(stdout, "DEREGISTERED\r\n");
                break;
            case STATE_BS_HOLD_OFF:
                fprintf(stdout, "CLIENT HOLD OFF\r\n");
                break;
            case STATE_BS_INITIATED:
                fprintf(stdout, "BOOTSTRAP INITIATED\r\n");
                break;
            case STATE_BS_PENDING:
                fprintf(stdout, "BOOTSTRAP PENDING\r\n");
                break;
            case STATE_BS_FINISHED:
                fprintf(stdout, "BOOTSTRAP FINISHED\r\n");
                break;
            case STATE_BS_FAILED:
                fprintf(stdout, "BOOTSTRAP FAILED\r\n");
                break;
            default:
                fprintf(stdout, "INVALID (%d)\r\n", (int)targetP->status);
            }
        }
    }

    if (lwm2mH->serverList == NULL)
    {
        fprintf(stdout, "No LWM2M Server.\r\n");
    }
    else
    {
        fprintf(stdout, "LWM2M Servers:\r\n");
        for (targetP = lwm2mH->serverList ; targetP != NULL ; targetP = targetP->next)
        {
            fprintf(stdout, " - Server ID %d", targetP->shortID);
            fprintf(stdout, "\tstatus: ");
            switch(targetP->status)
            {
            case STATE_DEREGISTERED:
                fprintf(stdout, "DEREGISTERED\r\n");
                break;
            case STATE_REG_PENDING:
                fprintf(stdout, "REGISTRATION PENDING\r\n");
                break;
            case STATE_REGISTERED:
                fprintf(stdout, "REGISTERED\tlocation: \"%s\"\tLifetime: %lus\r\n", targetP->location, (unsigned long)targetP->lifetime);
                break;
            case STATE_REG_UPDATE_PENDING:
                fprintf(stdout, "REGISTRATION UPDATE PENDING\r\n");
                break;
            case STATE_DEREG_PENDING:
                fprintf(stdout, "DEREGISTRATION PENDING\r\n");
                break;
            case STATE_REG_FAILED:
                fprintf(stdout, "REGISTRATION FAILED\r\n");
                break;
            default:
                fprintf(stdout, "INVALID (%d)\r\n", (int)targetP->status);
            }
        }
    }
}

static void prv_change(lwm2m_context_t * lwm2mH,
                       char * buffer,
                       void * user_data)
{
    lwm2m_uri_t uri;
    char * end = NULL;
    int result;

    /* unused parameter */
    (void)user_data;

    end = get_end_of_arg(buffer);
    if (end[0] == 0) goto syntax_error;

    result = lwm2m_stringToUri(buffer, end - buffer, &uri);
    if (result == 0) goto syntax_error;

    buffer = get_next_arg(end, &end);

    if (buffer[0] == 0)
    {
        fprintf(stderr, "report change!\n");
        lwm2m_resource_value_changed(lwm2mH, &uri);
    }
    else
    {
        handle_value_changed(lwm2mH, &uri, buffer, end - buffer);
    }
    return;

syntax_error:
    fprintf(stdout, "Syntax error !\n");
}

static void prv_object_list(lwm2m_context_t * lwm2mH,
                            char * buffer,
                            void * user_data)
{
    lwm2m_object_t * objectP;

    /* unused parameter */
    (void)user_data;

    for (objectP = lwm2mH->objectList; objectP != NULL; objectP = objectP->next)
    {
        if (objectP->instanceList == NULL)
        {
            fprintf(stdout, "/%d ", objectP->objID);
        }
        else
        {
            lwm2m_list_t * instanceP;

            for (instanceP = objectP->instanceList; instanceP != NULL ; instanceP = instanceP->next)
            {
                fprintf(stdout, "/%d/%d  ", objectP->objID, instanceP->id);
            }
        }
        fprintf(stdout, "\r\n");
    }
}

static void prv_instance_dump(lwm2m_context_t * lwm2mH,
                              lwm2m_object_t * objectP,
                              uint16_t id)
{
    int numData;
    lwm2m_data_t * dataArray;
    uint16_t res;

    numData = 0;
    res = objectP->readFunc(lwm2mH, id, &numData, &dataArray, objectP);
    if (res != COAP_205_CONTENT)
    {
        printf("Error ");
        print_status(stdout, res);
        printf("\r\n");
        return;
    }

    dump_tlv(stdout, numData, dataArray, 0);
}


static void prv_object_dump(lwm2m_context_t * lwm2mH,
                            char * buffer,
                            void * user_data)
{
    lwm2m_uri_t uri;
    char * end = NULL;
    int result;
    lwm2m_object_t * objectP;

    /* unused parameter */
    (void)user_data;

    end = get_end_of_arg(buffer);
    if (end[0] == 0) goto syntax_error;

    result = lwm2m_stringToUri(buffer, end - buffer, &uri);
    if (result == 0) goto syntax_error;
    if (LWM2M_URI_IS_SET_RESOURCE(&uri)) goto syntax_error;

    objectP = (lwm2m_object_t *)LWM2M_LIST_FIND(lwm2mH->objectList, uri.objectId);
    if (objectP == NULL)
    {
        fprintf(stdout, "Object not found.\n");
        return;
    }

    if (LWM2M_URI_IS_SET_INSTANCE(&uri))
    {
        prv_instance_dump(lwm2mH, objectP, uri.instanceId);
    }
    else
    {
        lwm2m_list_t * instanceP;

        for (instanceP = objectP->instanceList; instanceP != NULL ; instanceP = instanceP->next)
        {
            fprintf(stdout, "Instance %d:\r\n", instanceP->id);
            prv_instance_dump(lwm2mH, objectP, instanceP->id);
            fprintf(stdout, "\r\n");
        }
    }

    return;

syntax_error:
    fprintf(stdout, "Syntax error !\n");
}

static void prv_update(lwm2m_context_t * lwm2mH,
                       char * buffer,
                       void * user_data)
{
    /* unused parameter */
    (void)user_data;

    if (buffer[0] == 0) goto syntax_error;

    uint16_t serverId = (uint16_t) atoi(buffer);
    int res = lwm2m_update_registration(lwm2mH, serverId, false);
    if (res != 0)
    {
        fprintf(stdout, "Registration update error: ");
        print_status(stdout, res);
        fprintf(stdout, "\r\n");
    }
    return;

syntax_error:
    fprintf(stdout, "Syntax error !\n");
}

static void update_battery_level(lwm2m_context_t * context)
{
    static time_t next_change_time = 0;
    time_t tv_sec;

    tv_sec = lwm2m_gettime();
    if (tv_sec < 0) return;

    if (next_change_time < tv_sec)
    {
        char value[15];
        int valueLength;
        lwm2m_uri_t uri;
        int level = rand() % 100;

        if (0 > level) level = -level;
        if (lwm2m_stringToUri("/3/0/9", 6, &uri))
        {
            valueLength = sprintf(value, "%d", level);
            fprintf(stderr, "New Battery Level: %d\n", level);
            handle_value_changed(context, &uri, value, valueLength);
        }
        level = rand() % 20;
        if (0 > level) level = -level;
        next_change_time = tv_sec + level + 10;
    }
}

static void prv_add(lwm2m_context_t * lwm2mH,
                    char * buffer,
                    void * user_data)
{
    lwm2m_object_t * objectP;
    int res;

    /* unused parameter */
    (void)user_data;

    objectP = get_test_object();
    if (objectP == NULL)
    {
        fprintf(stdout, "Creating object 31024 failed.\r\n");
        return;
    }
    res = lwm2m_add_object(lwm2mH, objectP);
    if (res != 0)
    {
        fprintf(stdout, "Adding object 31024 failed: ");
        print_status(stdout, res);
        fprintf(stdout, "\r\n");
    }
    else
    {
        fprintf(stdout, "Object 31024 added.\r\n");
    }
    return;
}

static void prv_remove(lwm2m_context_t * lwm2mH,
                       char * buffer,
                       void * user_data)
{
    int res;

    /* unused parameter */
    (void)user_data;

    res = lwm2m_remove_object(lwm2mH, 31024);
    if (res != 0)
    {
        fprintf(stdout, "Removing object 31024 failed: ");
        print_status(stdout, res);
        fprintf(stdout, "\r\n");
    }
    else
    {
        fprintf(stdout, "Object 31024 removed.\r\n");
    }
    return;
}


static void prv_display_objects(lwm2m_context_t * lwm2mH,
                                char * buffer,
                                void * user_data)
{
    lwm2m_object_t * object;

    /* unused parameter */
    (void)user_data;

    for (object = lwm2mH->objectList; object != NULL; object = object->next){
        if (NULL != object) {
            switch (object->objID)
            {
            case LWM2M_SECURITY_OBJECT_ID:
                display_security_object(object);
                break;
            case LWM2M_SERVER_OBJECT_ID:
                display_server_object(object);
                break;
            case LWM2M_ACL_OBJECT_ID:
                break;
            case LWM2M_DEVICE_OBJECT_ID:
                display_device_object(object);
                break;
            case LWM2M_CONN_MONITOR_OBJECT_ID:
                break;
            case LWM2M_FIRMWARE_UPDATE_OBJECT_ID:
                display_firmware_object(object);
                break;
            case LWM2M_LOCATION_OBJECT_ID:
                display_location_object(object);
                break;
            case LWM2M_CONN_STATS_OBJECT_ID:
                break;
            case TEST_OBJECT_ID:
                display_test_object(object);
                break;
            }
        }
    }
}


static int ascii2uc(const char c, unsigned char *uc)
{
    if( ( c >= '0' ) && ( c <= '9' ) )
        *uc = c - '0';
    else if( ( c >= 'a' ) && ( c <= 'f' ) )
        *uc = c - 'a' + 10;
    else if( ( c >= 'A' ) && ( c <= 'F' ) )
        *uc = c - 'A' + 10;
    else
        return( -1 );

    return( 0 );
}


/**
 * \brief          This function decodes the hexadecimal representation of
 *                 data.
 *
 * \note           The output buffer can be the same as the input buffer. For
 *                 any other overlapping of the input and output buffers, the
 *                 behavior is undefined.
 *
 * \param obuf     Output buffer.
 * \param obufmax  Size in number of bytes of \p obuf.
 * \param ibuf     Input buffer.
 * \param len      The number of unsigned char written in \p obuf. This must
 *                 not be \c NULL.
 *
 * \return         \c 0 on success.
 * \return         \c -1 if the output buffer is too small or the input string
 *                 is not a valid hexadecimal representation.
 */
int unhexify( unsigned char *obuf, size_t obufmax,
              const char *ibuf, size_t *len )
{
    unsigned char uc, uc2;

    *len = strlen( ibuf );

    /* Must be even number of bytes. */
    if ( ( *len ) & 1 )
        return( -1 );
    *len /= 2;

    if ( (*len) > obufmax )
        return( -1 );

    while( *ibuf != 0 )
    {
        if ( ascii2uc( *(ibuf++), &uc ) != 0 )
            return( -1 );

        if ( ascii2uc( *(ibuf++), &uc2 ) != 0 )
            return( -1 );

        *(obuf++) = ( uc << 4 ) | uc2;
    }

    return( 0 );
}
#ifdef LWM2M_BOOTSTRAP
static void prv_initiate_bootstrap(lwm2m_context_t * lwm2mH,
                                   char * buffer,
                                   void * user_data)
{
    lwm2m_server_t * targetP;

    /* unused parameter */
    (void)user_data;

    // HACK !!!
    lwm2mH->state = STATE_BOOTSTRAP_REQUIRED;
    targetP = lwm2mH->bootstrapServerList;
    while (targetP != NULL)
    {
        targetP->lifetime = 0;
        targetP = targetP->next;
    }
}


static void prv_display_backup(lwm2m_context_t * lwm2mH,
                               char * buffer,
                               void * user_data)
{
   int i;

   /* unused parameters */
   (void)lwm2mH;
   (void)buffer;
   (void)user_data;

   for (i = 0 ; i < BACKUP_OBJECT_COUNT ; i++) {
       lwm2m_object_t * object = backupObjectArray[i];
       if (NULL != object) {
           switch (object->objID)
           {
           case LWM2M_SECURITY_OBJECT_ID:
               display_security_object(object);
               break;
           case LWM2M_SERVER_OBJECT_ID:
               display_server_object(object);
               break;
           default:
               break;
           }
       }
   }
}

static void prv_backup_objects(lwm2m_context_t * context)
{
    uint16_t i;

    for (i = 0; i < BACKUP_OBJECT_COUNT; i++) {
        if (NULL != backupObjectArray[i]) {
            switch (backupObjectArray[i]->objID)
            {
            case LWM2M_SECURITY_OBJECT_ID:
                clean_security_object(backupObjectArray[i]);
                lwm2m_free(backupObjectArray[i]);
                break;
            case LWM2M_SERVER_OBJECT_ID:
                clean_server_object(backupObjectArray[i]);
                lwm2m_free(backupObjectArray[i]);
                break;
            default:
                break;
            }
        }
        backupObjectArray[i] = (lwm2m_object_t *)lwm2m_malloc(sizeof(lwm2m_object_t));
        memset(backupObjectArray[i], 0, sizeof(lwm2m_object_t));
    }

    /*
     * Backup content of objects 0 (security) and 1 (server)
     */
    copy_security_object(backupObjectArray[0], (lwm2m_object_t *)LWM2M_LIST_FIND(context->objectList, LWM2M_SECURITY_OBJECT_ID));
    copy_server_object(backupObjectArray[1], (lwm2m_object_t *)LWM2M_LIST_FIND(context->objectList, LWM2M_SERVER_OBJECT_ID));
}

static void prv_restore_objects(lwm2m_context_t * context)
{
    lwm2m_object_t * targetP;

    /*
     * Restore content  of objects 0 (security) and 1 (server)
     */
    targetP = (lwm2m_object_t *)LWM2M_LIST_FIND(context->objectList, LWM2M_SECURITY_OBJECT_ID);
    // first delete internal content
    clean_security_object(targetP);
    // then restore previous object
    copy_security_object(targetP, backupObjectArray[0]);

    targetP = (lwm2m_object_t *)LWM2M_LIST_FIND(context->objectList, LWM2M_SERVER_OBJECT_ID);
    // first delete internal content
    clean_server_object(targetP);
    // then restore previous object
    copy_server_object(targetP, backupObjectArray[1]);

    // restart the old servers
    fprintf(stdout, "[BOOTSTRAP] ObjectList restored\r\n");
}

static void update_bootstrap_info(lwm2m_client_state_t * previousBootstrapState,
        lwm2m_context_t * context)
{
    if (*previousBootstrapState != context->state)
    {
        *previousBootstrapState = context->state;
        switch(context->state)
        {
            case STATE_BOOTSTRAPPING:
#ifdef LWM2M_WITH_LOGS
                fprintf(stdout, "[BOOTSTRAP] backup security and server objects\r\n");
#endif
                prv_backup_objects(context);
                break;
            default:
                break;
        }
    }
}

static void close_backup_object()
{
    int i;
    for (i = 0; i < BACKUP_OBJECT_COUNT; i++) {
        if (NULL != backupObjectArray[i]) {
            switch (backupObjectArray[i]->objID)
            {
            case LWM2M_SECURITY_OBJECT_ID:
                clean_security_object(backupObjectArray[i]);
                lwm2m_free(backupObjectArray[i]);
                break;
            case LWM2M_SERVER_OBJECT_ID:
                clean_server_object(backupObjectArray[i]);
                lwm2m_free(backupObjectArray[i]);
                break;
            default:
                break;
            }
        }
    }
}
#endif /* LWM2M_BOOTSTRAP */


#define PARAMETER_ERROR -1
#define FILE_IO_ERROR -2
#define ALLOC_FAILED -3

int load_pem_file( const char *path, unsigned char **buf, size_t *n )
{
    FILE *f;
    long size;

    if ( path == NULL ) return PARAMETER_ERROR;
    if ( buf == NULL ) return PARAMETER_ERROR;
    if ( n == NULL ) return PARAMETER_ERROR;

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( FILE_IO_ERROR );

    fseek( f, 0, SEEK_END );
    if( ( size = ftell( f ) ) == -1 )
    {
        fclose( f );
        return( FILE_IO_ERROR );
    }
    fseek( f, 0, SEEK_SET );

    *n = (size_t) size;

    if( *n + 1 == 0 ||
        ( *buf = malloc( *n + 1 ) ) == NULL )
    {
        fclose( f );
        return( ALLOC_FAILED );
    }

    if( fread( *buf, 1, *n, f ) != *n )
    {
        fclose( f );

        memset( *buf, 0 , *n );
        free( *buf );

        return( FILE_IO_ERROR );
    }

    fclose( f );

    (*buf)[*n] = '\0';
    *n=*n+1;
    return 0;
}

void print_usage(void)
{
    fprintf(stdout, "Usage: lwm2mclient [OPTION]\r\n");
    fprintf(stdout, "Launch a LwM2M client.\r\n");
    fprintf(stdout, "Options:\r\n");
    fprintf(stdout, "  -n NAME\tSet the endpoint name of the Client. Default: testlwm2mclient\r\n");
    fprintf(stdout, "  -l PORT\tSet the local UDP port of the Client. Default: 56830\r\n");
    fprintf(stdout, "  -h HOST\tSet the hostname of the LWM2M Server to connect to. Default: localhost\r\n");
    fprintf(stdout, "  -p PORT\tSet the port of the LWM2M Server to connect to. Default: "LWM2M_STANDARD_PORT_STR"\r\n");
    fprintf(stdout, "  -4\t\tUse IPv4. Default: IPv6 and IPv4\r\n");
    fprintf(stdout, "  -6\t\tUse IPv6. Default: IPv6 and IPv4\r\n");
    fprintf(stdout, "  -t TIME\tSet the lifetime of the Client. Default: 300\r\n");
    fprintf(stdout, "  -b\t\tBootstrap requested.\r\n");
    fprintf(stdout, "  -c\t\tChange battery level over time.\r\n");
    fprintf(stdout, "  -S BYTES\tCoAP block size. Options: 16, 32, 64, 128, 256, 512, 1024. Default: %" PRIu16 "\r\n",
            LWM2M_COAP_DEFAULT_BLOCK_SIZE);
#if defined WITH_TINYDTLS
    fprintf(stdout, "  -i STRING\tSet the device management or bootstrap server PSK identity. If not set use none secure mode\r\n");
    fprintf(stdout, "  -s HEXSTRING\tSet the device management or bootstrap server Pre-Shared-Key. If not set use none secure mode\r\n");
#endif /* WITH_TINYDTLS */

#if defined(WITH_MBEDTLS) 
    fprintf(stdout, "  -force_ciphersuite=VALUE\tForce the use of a specific TLS ciphersuite\r\n");
#if defined(MBEDTLS_DEBUG_C)
    fprintf(stdout, "  -debug_level=VALUE\tDefines the debug level\r\n");
#endif /* MBEDTLS_DEBUG_C */
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    fprintf(stdout, "  -cid=VALUE\tDisable (0) or enable (1) the use of the DTLS Connection ID extension\r\n");
    fprintf(stdout, "  -cid_val=HEXSTRING\tThe CID to use for incoming messages (in hex, without 0x)\r\n");
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    fprintf(stdout, "  -sni=STRING\t\tDefines the Server Name Indication (SNI)\r\n");
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
    fprintf(stdout, "  -psk_identity=STRING\tPSK identity\r\n");
    fprintf(stdout, "  -psk=HEXSTRING\tPre-Shared Key\r\n");
#endif /* MBEDTLS_KEY_EXCHANGE_PSK_ENABLED */

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_FS_IO)
    fprintf(stdout, "  -ca_file=STRING\tThe single file containing the top-level CA(s) you fully trust\r\n");
    fprintf(stdout, "  -ca_path=STRING\tThe path containing the top-level CA(s) you fully trust\r\n");
    fprintf(stdout, "  -crt_file=STRING\tThe own cert and chain (in bottom to top order, top may be omitted)\r\n");
    fprintf(stdout, "  -key_file=STRING\tThe own private key\r\n");
#endif /* MBEDTLS_X509_CRT_PARSE_C && MBEDTLS_FS_IO */

#if defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_X509_CRT_PARSE_C)
    fprintf(stdout, "  -key_opaque=VALUE\tHandle your private key as if it were opaque. 0 for disabled\r\n"); 
#endif /* MBEDTLS_USE_PSA_CRYPTO && MBEDTLS_X509_CRT_PARSE_C */

#endif /* WITH_MBEDTLS */
    fprintf(stdout, "\r\n");
}

int main(int argc, char *argv[])
{
    client_data_t data;
    sec_context_t options;
    int result;
    lwm2m_context_t * lwm2mH = NULL;
    const char * localPort = "56830";
    const char * server = NULL;
    const char * serverPort = LWM2M_STANDARD_PORT_STR;
    char * name = "testlwm2mclient";
    int lifetime = 300;
    int batterylevelchanging = 0;
    time_t reboot_time = 0;
    int opt;
    bool bootstrapRequested = false;
    bool serverPortChanged = false;

#ifdef LWM2M_BOOTSTRAP
    lwm2m_client_state_t previousState = STATE_INITIAL;
#endif

    uint8_t securityMode = LWM2M_SECURITY_MODE_NONE;
    char serverUri[50];
    int serverId = 123;

    memset(&data, 0, sizeof(client_data_t));

#if defined(WITH_TINYDTLS) || defined(WITH_MBEDTLS)
    data.secContext=(sec_context_t*)malloc(sizeof(sec_context_t));
    if (data.secContext==NULL)
    {
            fprintf(stdout, "Not enough memory.\r\n ");
            return(-1);
    }
#endif /* WITH_TINYDTLS || WITH_MBEDTLS */

#if defined WITH_TINYDTLS || defined WITH_MBEDTLS
    /* PSK-based security mode */
    options.psk = NULL;
    char *psk = NULL;
    char *psk_identity = NULL;
#endif /* WITH_TINYDTLS || WITH_MBEDTLS */

#if defined WITH_MBEDTLS
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    rng_context_t rng;
#endif /* MBEDTLS_X509_CRT_PARSE_C */ 

    int ret;
  
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status;
#endif

#endif /* WITH_MBEDTLS */
    char *p, *q;
    bool secure_coap;
    int param_match=0;

    /*
     * The function start by setting up the command line interface (which may or not be useful depending on your project)
     *
     * This is an array of commands describes as { name, description, long description, callback, userdata }.
     * The firsts tree are easy to understand, the callback is the function that will be called when this command is typed
     * and in the last one will be stored the lwm2m context (allowing access to the server settings and the objects).
     */
    command_desc_t commands[] =
    {
            {"list", "List known servers.", NULL, prv_output_servers, NULL},
            {"change", "Change the value of resource.", " change URI [DATA]\r\n"
                                                        "   URI: uri of the resource such as /3/0, /3/0/2\r\n"
                                                        "   DATA: (optional) new value\r\n", prv_change, NULL},
            {"update", "Trigger a registration update", " update SERVER\r\n"
                                                        "   SERVER: short server id such as 123\r\n", prv_update, NULL},
#ifdef LWM2M_BOOTSTRAP
            {"bootstrap", "Initiate a DI bootstrap process", NULL, prv_initiate_bootstrap, NULL},
            {"dispb", "Display current backup of objects/instances/resources\r\n"
                    "\t(only security and server objects are backupped)", NULL, prv_display_backup, NULL},
#endif
            {"ls", "List Objects and Instances", NULL, prv_object_list, NULL},
            {"disp", "Display current objects/instances/resources", NULL, prv_display_objects, NULL},
            {"dump", "Dump an Object", "dump URI"
                                       "URI: uri of the Object or Instance such as /3/0, /1\r\n", prv_object_dump, NULL},
            {"add", "Add support of object 31024", NULL, prv_add, NULL},
            {"rm", "Remove support of object 31024", NULL, prv_remove, NULL},
            {"quit", "Quit the client gracefully.", NULL, prv_quit, NULL},
            {"^C", "Quit the client abruptly (without sending a de-register message).", NULL, NULL, NULL},

            COMMAND_END_LIST
    };

    // Three options for the address family: AF_INET, AF_INET6 or AF_UNSPEC
    data.addressFamily = AF_INET;

    /* Setting default values for options */
#if defined(WITH_MBEDTLS)

#if defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_X509_CRT_PARSE_C)
    options.key_opaque = 0; // do not use opaque keys
#endif /* MBEDTLS_USE_PSA_CRYPTO && MBEDTLS_X509_CRT_PARSE_C */
#if defined(MBEDTLS_DEBUG_C)
    options.debug_level = 0; // no debugging
#endif /* MBEDTLS_DEBUG_C */
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)  
    options.cid_enabled = MBEDTLS_SSL_CID_DISABLED;
    char *cid = NULL;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_FS_IO)
    options.ca_file = NULL;
    options.crt_file = NULL;
    options.key_file = NULL;
#endif /* MBEDTLS_X509_CRT_PARSE_C && MBEDTLS_FS_IO */
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    options.sni = NULL;
    options.sni_len = 0;
    char *sni = NULL;
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
    options.force_ciphersuite[0] = 0; // default for ciphersuite
#endif /* WITH_MBEDTLS */

    opt = 1;
    while (opt < argc)
    {
        p = argv[opt];

        if( strcmp( p, "-b" ) == 0 )
        {
            bootstrapRequested = true;
#if defined(WITH_MBEDTLS)
            if (!serverPortChanged) serverPort = LWM2M_DTLS_BSSERVER_PORT_STR;
#else            
            if (!serverPortChanged) serverPort = LWM2M_BSSERVER_PORT_STR;
#endif /* WITH_MBEDTLS */
            param_match = 1;
        }
        else if( strcmp( p, "-c" ) == 0 )
        {
            batterylevelchanging = 1;
            param_match = 1;
        }
        else if( strcmp( p, "-t" ) == 0 )
        {
            opt++;
            if (opt >= argc)
            {
                print_usage();
                return 0;
            }
            if (1 != sscanf(argv[opt], "%d", &lifetime))
            {
                print_usage();
                return 0;
            }
            param_match = 1;
        }
        else if( strcmp( p, "-n" ) == 0 )
        {
            opt++;
            if (opt >= argc)
            {
                print_usage();
                return 0;
            }
            name = argv[opt];
            param_match = 1;
        }
        else if( strcmp( p, "-l" ) == 0 )
        {
            opt++;
            if (opt >= argc)
            {
                print_usage();
                return 0;
            }
            localPort = argv[opt];
            param_match = 1;
        }
        else if( strcmp( p, "-h" ) == 0 )
        {
            opt++;
            if (opt >= argc)
            {
                print_usage();
                return 0;
            }
            server = argv[opt];
            param_match = 1;
        }
#if defined WITH_TINYDTLS 
        else if( strcmp( p, "-i" ) == 0 )
        {
            psk = q;
            opt++;
            continue;
        }
        else if( strcmp( p, "-s" ) == 0 )
        {
            psk_identity = q;
            opt++;
            continue;
        }
#endif /* WITH_TINYDTLS */
        else if( strcmp( p, "-p" ) == 0 )
        {
            opt++;
            if (opt >= argc)
            {
                print_usage();
                return 0;
            }
            serverPort = argv[opt];
            serverPortChanged = true;
            param_match = 1;
        }        
        else if( strcmp( p, "-4" ) == 0 )
        {
            data.addressFamily = AF_INET;
            param_match = 1;
        }
        else if( strcmp( p, "-6" ) == 0 )
        {
            data.addressFamily = AF_INET6;
            param_match = 1;
        }        
        else if( strcmp( p, "-S" ) == 0 )
        {
            param_match = 1;
            opt++;
            if (opt >= argc) {
                print_usage();
                return 0;
            }
            uint16_t coap_block_size_arg;
            if (1 == sscanf(argv[opt], "%" SCNu16, &coap_block_size_arg) &&
                lwm2m_set_coap_block_size(coap_block_size_arg)) {
                break;
            } else {
                print_usage();
                return 0;
            }
        } 
        
        if (param_match == 1)
        {
           opt += 1;
           param_match = 0;
           continue;
        }

        if( ( q = strchr( p, '=' ) ) != NULL )
        {
            *q++ = '\0';
        }

#if defined(WITH_MBEDTLS) 

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_FS_IO)
        if( strcmp( p, "-ca_file" ) == 0 )
        {
            options.ca_file = q;
            opt++;
            continue;
        }
        if( strcmp( p, "-crt_file" ) == 0 )
        {
            options.crt_file = q;
            opt++;
            continue;
        }
        if( strcmp( p, "-key_file" ) == 0 )
        {
            options.key_file = q;
            opt++;
            continue;
        }        
#endif /* MBEDTLS_X509_CRT_PARSE_C && MBEDTLS_FS_IO */

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
        if( strcmp( p, "-sni" ) == 0 )
        {
            sni = q;
            opt++;
            continue;
        }
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
        if( strcmp( p, "-cid" ) == 0 )
        {
            options.cid_enabled = atoi( q );
            if( options.cid_enabled != MBEDTLS_SSL_CID_ENABLED && 
                options.cid_enabled != MBEDTLS_SSL_CID_DISABLED )
            {
                print_usage();
                return 0;
            }
            opt++;
            continue;
        }

        if( strcmp( p, "-cid_val" ) == 0 )
        {
            cid = q;
            opt++;
            continue;
        }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

#if defined(MBEDTLS_DEBUG_C)
        if( strcmp( p, "-debug_level" ) == 0 )
        {
            options.debug_level = atoi( q );
            if( options.debug_level < 0 || options.debug_level > 65535 )
            {
                print_usage();
                return 0;
            }
            opt++;
            continue;
        }
#endif /* MBEDTLS_DEBUG_C */

        if( strcmp( p, "-force_ciphersuite" ) == 0 )
        {
            options.force_ciphersuite[0] = mbedtls_ssl_get_ciphersuite_id( q );

            if( options.force_ciphersuite[0] == 0 )
            {
                const int *list;
                list = mbedtls_ssl_list_ciphersuites();
                while( *list )
                {
                    fprintf(stdout," %-42s", mbedtls_ssl_get_ciphersuite_name( *list ) );
                    list++;
                    if( !*list )
                        break;
                    fprintf(stdout," %s\n", mbedtls_ssl_get_ciphersuite_name( *list ) );
                    list++;
                }
                fprintf(stdout,"\n");
                return 0;
            }
            options.force_ciphersuite[1] = 0;
            opt++;
            continue;
        }
#if defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_X509_CRT_PARSE_C)
        if( strcmp( p, "-key_opaque" ) == 0 )
        {
            options.key_opaque = atoi( q );
            opt++;
            continue;
        }
#endif /* MBEDTLS_USE_PSA_CRYPTO && MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
        if( strcmp( p, "-psk" ) == 0 )
        {
            psk = q;
            opt++;
            continue;
        }
        if( strcmp( p, "-psk_identity" ) == 0 )
        {
            psk_identity = q;
            opt++;
            continue;
        }
#endif /* MBEDTLS_KEY_EXCHANGE_PSK_ENABLED */
#endif /* WITH_MBEDTLS */

        /* No parameter matches */
        if (param_match == 0)
        {
            print_usage();
            return 0;
        };

    }

    /* Initialize Crypto */

#if defined(WITH_MBEDTLS) && defined(MBEDTLS_USE_PSA_CRYPTO)
    status = psa_crypto_init();
    if( status != PSA_SUCCESS )
    {
        fprintf(stderr, "Failed to initialize PSA Crypto implementation: %d\n",
                         (int) status );
        return -1;
    }
#endif /* WITH_MBEDTLS && MBEDTLS_USE_PSA_CRYPTO */


#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( options.debug_level );
#endif /* MBEDTLS_DEBUG_C */

    if (!server)
    {
        server = (AF_INET == data.addressFamily ? DEFAULT_SERVER_IPV4 : DEFAULT_SERVER_IPV6);
    }

    /* Create a socket */
#if defined LWM2M_CLIENT_MODE 
    data.sock = socket(data.addressFamily, SOCK_DGRAM, 0);
#else 
    data.sock = create_socket(localPort, data.addressFamily);
#endif /* LWM2M_CLIENT_MODE */
    if (data.sock < 0)
    {
        fprintf(stderr, "Failed to open socket: %d %s\r\n", errno, strerror(errno));
        return -1;
    }

    /*
     * The PSK and the CID parameters are hex-encoded and need to be converted first.
     * The certificates and private keys need to be loaded from file.
     */
#if defined(WITH_TINYDTLS) || ( defined(WITH_MBEDTLS) && defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) )
    if (psk != NULL)
    {
        options.psk_len = strlen((const char *) psk) / 2;

        options.psk = malloc(options.psk_len);
        if (options.psk == NULL)
        {
            fprintf(stderr, "Failed to allocate buffer for PSK\r\n");
            return -1;
        }

        if( unhexify( data.secContext->psk, options.psk_len,
                    psk, &options.psk_len ) != 0 )
        {
            fprintf(stderr, "PSK not valid\n" );
            return -1;
        }
    }
#endif /* WITH_TINYDTLS || WITH_MBEDTLS && MBEDTLS_KEY_EXCHANGE_PSK_ENABLED */

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    if (sni != NULL )
    {
        options.sni = strdup( (const char *) sni);
        if (options.sni == NULL)
        {
            fprintf(stderr, "Not enough memory for SNI available\n" );
            return -1;
        }
        options.sni_len = (uint8_t) strlen( (const char *) sni);
    }
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(WITH_MBEDTLS) && defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    if (strlen(cid) > 0 )
    {
        if( unhexify( options.cid, sizeof( options.cid ),
                    cid, &options.cid_len ) != 0 )
        {
            fprintf(stderr, "CID not valid\n" );
            return -1;
        }
    }
#endif /* WITH_MBEDTLS && MBEDTLS_SSL_DTLS_CONNECTION_ID */


#if defined(WITH_TINYDTLS) || ( defined(WITH_MBEDTLS) && defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) )
    if (psk_identity != NULL)
    {
        options.psk_identity = (uint8_t*) strdup( (const char *) psk_identity);
        if (options.psk_identity == NULL)
        {
            fprintf(stderr, "Not enough memory for PSK Identity available\n" );
            return -1;
        }
        options.psk_identity_len = (uint16_t) strlen( (const char *) psk_identity);
    }
#endif /* WITH_TINYDTLS || WITH_MBEDTLS && MBEDTLS_KEY_EXCHANGE_PSK_ENABLED */

#if defined(WITH_TINYDTLS) || defined(WITH_MBEDTLS)
    sprintf(serverUri, "coaps://%s:%s", server, serverPort);
    secure_coap=true;
#else
    sprintf(serverUri, "coap://%s:%s", server, serverPort);
    secure_coap=false;
#endif /* WITH_TINYDTLS || WITH_MBEDTLS */

    /* Determine security mode */
#if defined(WITH_TINYDTLS) || ( defined(WITH_MBEDTLS) && defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) )
    if (options.psk_identity_len > 0 && options.psk_len > 0)
    {
        securityMode = LWM2M_SECURITY_MODE_PRE_SHARED_KEY;
    } else 
#endif /* WITH_TINYDTLS || (WITH_MBEDTLS && MBEDTLS_KEY_EXCHANGE_PSK_ENABLED ) */
#if defined(WITH_MBEDTLS)
    if (secure_coap == true && securityMode!=LWM2M_SECURITY_MODE_PRE_SHARED_KEY)
    {
        securityMode = LWM2M_SECURITY_MODE_CERTIFICATE;
    } else 
#endif /* WITH_MBEDTLS */
    {   
        securityMode = LWM2M_SECURITY_MODE_NONE;
    }

#if defined(WITH_MBEDTLS) && defined(MBEDTLS_X509_CRT_PARSE_C)
    /* Load Client public key */
    ret = load_pem_file(options.crt_file, (unsigned char**) &options.clicert, &options.clicert_len);
    if (ret < 0)
    {
        fprintf(stderr, "Unable to load %s\n", options.crt_file);
        return -1;
    }

    /* Load Client secret key */
    ret = load_pem_file(options.key_file, (unsigned char**) &options.pkey, &options.pkey_len);
    if (ret < 0)
    {
        fprintf(stderr, "Unable to load %s\n", options.key_file);
        return -1;
    }

    /* Load Server public key = CA cert */
    ret = load_pem_file(options.ca_file, (unsigned char**) &options.cacert, &options.cacert_len);
    if (ret < 0)
    {
        fprintf(stderr, "Unable to load %s\n", options.ca_file);
        return -1;
    }
#endif /* WITH_MBEDTLS && MBEDTLS_X509_CRT_PARSE_C */

    data.secContext = &options;

    if (securityMode == LWM2M_SECURITY_MODE_CERTIFICATE || securityMode == LWM2M_SECURITY_MODE_PRE_SHARED_KEY)
    {
        /* Create LwM2M Security Object */
        objArray[0] = get_security_object(serverId, 
                                          serverUri, 
                                          &options,
                                          bootstrapRequested, 
                                          securityMode);

    } else
    if (securityMode == LWM2M_SECURITY_MODE_NONE)
    {
        objArray[0] = get_security_object(serverId, 
                                          serverUri,
                                          NULL,
                                          false,
                                          LWM2M_SECURITY_MODE_NONE);
    } else
    {
        fprintf(stderr, "Unsupported security mode\r\n");
        return -1;        
    }

    if (NULL == objArray[0])
    {
        fprintf(stderr, "Failed to create security object\r\n");
        return -1;
    }
    data.securityObjP = objArray[0];

    objArray[1] = get_server_object(serverId, "U", lifetime, false);
    if (NULL == objArray[1])
    {
        fprintf(stderr, "Failed to create server object\r\n");
        return -1;
    }

    objArray[2] = get_object_device();
    if (NULL == objArray[2])
    {
        fprintf(stderr, "Failed to create Device object\r\n");
        return -1;
    }

    objArray[3] = get_object_firmware();
    if (NULL == objArray[3])
    {
        fprintf(stderr, "Failed to create Firmware object\r\n");
        return -1;
    }

    objArray[4] = get_object_location();
    if (NULL == objArray[4])
    {
        fprintf(stderr, "Failed to create location object\r\n");
        return -1;
    }

    objArray[5] = get_test_object();
    if (NULL == objArray[5])
    {
        fprintf(stderr, "Failed to create test object\r\n");
        return -1;
    }

    objArray[6] = get_attestation_object();
    if (NULL == objArray[6])
    {
        fprintf(stderr, "Failed to create test object\r\n");
        return -1;
    }

    objArray[7] = get_object_conn_m();
    if (NULL == objArray[7])
    {
        fprintf(stderr, "Failed to create connectivity monitoring object\r\n");
        return -1;
    }

    objArray[8] = get_object_conn_s();
    if (NULL == objArray[8])
    {
        fprintf(stderr, "Failed to create connectivity statistics object\r\n");
        return -1;
    }

    int instId = 0;
    objArray[9] = acc_ctrl_create_object();
    if (NULL == objArray[9])
    {
        fprintf(stderr, "Failed to create Access Control object\r\n");
        return -1;
    }
    else if (acc_ctrl_obj_add_inst(objArray[8], instId, 3, 0, serverId)==false)
    {
        fprintf(stderr, "Failed to create Access Control object instance\r\n");
        return -1;
    }
    else if (acc_ctrl_oi_add_ac_val(objArray[8], instId, 0, 0xF /* == 0b000000000001111 */)==false)
    {
        fprintf(stderr, "Failed to create Access Control ACL default resource\r\n");
        return -1;
    }
    else if (acc_ctrl_oi_add_ac_val(objArray[8], instId, 999, 0x1 /* == 0b000000000000001 */)==false)
    {
        fprintf(stderr, "Failed to create Access Control ACL resource for serverId: 999\r\n");
        return -1;
    }
    /*
     * The liblwm2m library is now initialized with the functions that will be in
     * charge of communication
     */
    lwm2mH = lwm2m_init(&data);
    if (NULL == lwm2mH)
    {
        fprintf(stderr, "lwm2m_init() failed\r\n");
        return -1;
    }
    data.ctx = lwm2mH;
    data.connLayer = connectionlayer_create(lwm2mH);

    /*
     * We configure the liblwm2m library with the name of the client - which shall be unique for each client -
     * the number of objects we will be passing through and the objects array
     */
    result = lwm2m_configure(lwm2mH, name, NULL, NULL, OBJ_COUNT, objArray);
    if (result != 0)
    {
        fprintf(stderr, "lwm2m_configure() failed: 0x%X\r\n", result);
        return -1;
    }

    signal(SIGINT, handle_sigint);

    /**
     * Initialize value changed callback.
     */
    init_value_change(lwm2mH);

    fprintf(stdout, "LwM2M Client \"%s\" started on port %s\r\n", name, localPort);
    fprintf(stdout, "> "); fflush(stdout);
    /*
     * We now enter in a while loop that will handle the communications from the server
     */
    while (0 == g_quit)
    {
        struct timeval tv;
        fd_set readfds;

        if (g_reboot)
        {
            time_t tv_sec;

            tv_sec = lwm2m_gettime();

            if (0 == reboot_time)
            {
                reboot_time = tv_sec + 5;
            }
            if (reboot_time < tv_sec)
            {
                /*
                 * Message should normally be lost with reboot ...
                 */
                fprintf(stderr, "reboot time expired, rebooting ...");
                system_reboot();
            }
            else
            {
                tv.tv_sec = reboot_time - tv_sec;
            }
        }
        else if (batterylevelchanging)
        {
            update_battery_level(lwm2mH);
            tv.tv_sec = 5;
        }
        else
        {
            tv.tv_sec = 60;
        }
        tv.tv_usec = 0;

        FD_ZERO(&readfds);
        FD_SET(data.sock, &readfds);
        FD_SET(STDIN_FILENO, &readfds);

        /*
         * This function does two things:
         *  - first it does the work needed by liblwm2m (eg. (re)sending some packets).
         *  - Secondly it adjusts the timeout value (default 60s) depending on the state of the transaction
         *    (eg. retransmission) and the time between the next operation
         */
        result = lwm2m_step(lwm2mH, &(tv.tv_sec));

        switch (lwm2mH->state)
        {
        case STATE_INITIAL:
            fprintf(stdout, "STATE_INITIAL\r\n");
            break;
        case STATE_BOOTSTRAP_REQUIRED:
            fprintf(stdout, "STATE_BOOTSTRAP_REQUIRED\r\n");
            break;
        case STATE_BOOTSTRAPPING:
            fprintf(stdout, "STATE_BOOTSTRAPPING\r\n");
            break;
        case STATE_REGISTER_REQUIRED:
            fprintf(stdout, "STATE_REGISTER_REQUIRED\r\n");
            break;
        case STATE_REGISTERING:
            fprintf(stdout, "STATE_REGISTERING\r\n");
            break;
        case STATE_READY:
            fprintf(stdout, "STATE_READY\r\n");
            break;
        default:
            fprintf(stdout, "Unknown...\r\n");
            break;
        }
        if (result != 0)
        {
#ifdef LWM2M_BOOTSTRAP
            fprintf(stderr, "lwm2m_step() failed: 0x%X\r\n", result);
            if(previousState == STATE_BOOTSTRAPPING)
            {
#ifdef LWM2M_WITH_LOGS
                fprintf(stdout, "[BOOTSTRAP] restore security and server objects\r\n");
#endif /* LWM2M_WITH_LOGS */
                prv_restore_objects(lwm2mH);
                lwm2mH->state = STATE_INITIAL;
            }
            else return -1;
#else
        return -1;
#endif /* LWM2M_BOOTSTRAP */
        }

#ifdef LWM2M_BOOTSTRAP
        update_bootstrap_info(&previousState, lwm2mH);
#endif /* LWM2M_BOOTSTRAP */


        /*
         * This part will set up an interruption until an event happen on SDTIN or the socket until "tv" timed out (set
         * with the precedent function)
         */
        result = select(FD_SETSIZE, &readfds, NULL, NULL, &tv);

        if (result < 0)
        {
            if (errno != EINTR)
            {
              fprintf(stderr, "Error in select(): %d %s\r\n", errno, strerror(errno));
            }
        }
        else if (result > 0)
        {
            uint8_t buffer[MAX_PACKET_SIZE];
            ssize_t numBytes;

            /*
             * If an event happens on the socket
             */
            if (FD_ISSET(data.sock, &readfds))
            {
                struct sockaddr_storage addr;
                socklen_t addrLen;

                addrLen = sizeof(addr);

                /*
                 * We retrieve the data received
                 */
                numBytes = recvfrom(data.sock, buffer, MAX_PACKET_SIZE, 0, (struct sockaddr *)&addr, &addrLen);

                if (0 > numBytes)
                {
                    fprintf(stderr, "Error in recvfrom(): %d %s\r\n", errno, strerror(errno));
                }
                else if (numBytes >= MAX_PACKET_SIZE) 
                {
                    fprintf(stderr, "Received packet >= MAX_PACKET_SIZE\r\n");
                }
                else if (0 < numBytes)
                {
                    char s[INET6_ADDRSTRLEN];
                    in_port_t port;
                    connection_t *connP;
                    if (AF_INET == addr.ss_family) {
                        struct sockaddr_in *saddr = (struct sockaddr_in *)&addr;
                        inet_ntop(saddr->sin_family, &saddr->sin_addr, s, INET_ADDRSTRLEN);
                        port = saddr->sin_port;
                    }
                    else if (AF_INET6 == addr.ss_family)
                    {
                        struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)&addr;
                        inet_ntop(saddr->sin6_family, &saddr->sin6_addr, s, INET6_ADDRSTRLEN);
                        port = saddr->sin6_port;
                    }
                    fprintf(stderr, "%zd bytes received from [%s]:%hu\r\n", numBytes, s, ntohs(port));

                    /* Display received data */
#ifdef LWM2M_WITH_LOGS
                    output_buffer(stderr, buffer, (size_t)numBytes, 0);
#endif /* LWM2M_WITH_LOGS */

                    connP = connectionlayer_find_connection(data.connLayer, &addr, addrLen);
                    if (connP != NULL)
                    {
                        /*
                         * Let liblwm2m respond to the query depending on the context
                         */
                        connectionlayer_handle_packet(data.connLayer, &addr, addrLen, buffer, numBytes);
                        conn_s_updateRxStatistic(objArray[7], numBytes, false);
                    }
                    else
                    {
                        fprintf(stderr, "received bytes ignored!\r\n");
                    }
                }
            }

            /*
             * If the event happened on the SDTIN
             */
            else if (FD_ISSET(STDIN_FILENO, &readfds))
            {
                numBytes = read(STDIN_FILENO, buffer, MAX_PACKET_SIZE - 1);

                if (numBytes > 1)
                {
                    buffer[numBytes] = 0;
                    /*
                     * We call the corresponding callback of the typed command passing it the buffer for further arguments
                     */
                    handle_command(lwm2mH, commands, (char*)buffer);
                }
                if (g_quit == 0)
                {
                    fprintf(stdout, "\r\n> ");
                    fflush(stdout);
                }
                else
                {
                    fprintf(stdout, "\r\n");
                }
            }
        }
    }

    /*
     * Finally when the loop is left smoothly - asked by user in the command line interface - we unregister our client from it
     */
    if (g_quit == 1)
    {
#if defined(WITH_TINYDTLS) || ( defined(WITH_MBEDTLS) && defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) )
        free(data.secContext->psk_identity);
        free(data.secContext->psk);
#endif

#ifdef LWM2M_BOOTSTRAP
        close_backup_object();
#endif
        lwm2m_close(lwm2mH);
    }

    close(data.sock);
    connectionlayer_free(data.connLayer);

#if defined(WITH_MBEDTLS)

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    lwm2m_free( options.clicert );
    lwm2m_free( options.cacert );
    lwm2m_free( options.pkey );
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    lwm2m_free(options.sni);
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
 
#endif /* WITH_MBEDTLS */

#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) || defined(WITH_TINYDTLS)
    lwm2m_free( options.psk );
    lwm2m_free( options.psk_identity );
#endif /* MBEDTLS_KEY_EXCHANGE_PSK_ENABLED || WITH_TINYDTLS */

    clean_security_object(objArray[0]);
    lwm2m_free(objArray[0]);
    clean_server_object(objArray[1]);
    lwm2m_free(objArray[1]);
    free_object_device(objArray[2]);
    free_object_firmware(objArray[3]);
    free_object_location(objArray[4]);
    free_test_object(objArray[5]);
    free_object_conn_m(objArray[6]);
    free_object_conn_s(objArray[7]);
    acl_ctrl_free_object(objArray[8]);

#if defined(WITH_MBEDTLS) && defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_destroy_key( data.secContext->key_slot );
    mbedtls_psa_crypto_free( );
#endif /* WITH_MBEDTLS && MBEDTLS_USE_PSA_CRYPTO */

#if defined(WITH_MBEDTLS) && defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt_free( &data.secContext->mbedtls_cacert );
    mbedtls_x509_crt_free( &data.secContext->mbedtls_clicert );
    mbedtls_pk_free( &data.secContext->mbedtls_pkey );
#endif /* WITH_MBEDTLS && MBEDTLS_X509_CRT_PARSE_C */

#ifdef MEMORY_TRACE
    if (g_quit == 1)
    {
        trace_print(0, 1);
    }
#endif

    return 0;
}
