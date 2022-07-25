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
 *    domedambrosio - Please refer to git log
 *    Fabien Fleutot - Please refer to git log
 *    Axel Lorente - Please refer to git log
 *    Achim Kraus, Bosch Software Innovations GmbH - Please refer to git log
 *    Pascal Rieux - Please refer to git log
 *    Ville Skyttä - Please refer to git log
 *    Scott Bertin, AMETEK, Inc. - Please refer to git log
 *    Tuve Nordius, Husqvarna Group - Please refer to git log
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

*/


#include "liblwm2m.h"
#include "lwm2mclient.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define RES_M_NONCE         0
#define RES_M_TOKEN         1


extern size_t generate_token(uint8_t *challenge , uint8_t  **token_buf);

typedef struct
{
    uint8_t   *token;
    uint8_t    nonce[32];
    uint8_t   token_size;
} attestation_data_t;

static uint8_t prv_res2tlv(lwm2m_data_t* dataP,
                           attestation_data_t* attDataP)
{
    uint8_t ret = COAP_205_CONTENT; 

    switch (dataP->id)    
    {
    case RES_M_TOKEN:
        if(attDataP->token_size > 0 )
        {
            unsigned char *arr = (unsigned char*)lwm2m_malloc(2*attDataP->token_size);
            for(int i=0,j=0; i<attDataP->token_size; i++,j=j+2){
                sprintf(arr+j,"%02x",attDataP->token[i]);
            }
           
            free(attDataP->token);
            lwm2m_data_encode_string((unsigned char*) arr, dataP);
            free(arr);
            attDataP->token_size = 0;
        }
        else
            return COAP_412_PRECONDITION_FAILED;
    
    break;
    default:
            ret = COAP_404_NOT_FOUND;
    break;
    }
    
    return ret;
}

int isnum(char a){

    if(a >= '0' && a <='9')
        return 1;
    else return 0;
}

static uint8_t prv_nonce_write(lwm2m_context_t *contextP,
                                uint16_t instanceId,
                                int numData,
                                lwm2m_data_t * dataArray,
                                lwm2m_object_t * objectP,
                                lwm2m_write_type_t writeType)
{
    uint8_t result = COAP_500_INTERNAL_SERVER_ERROR;
    attestation_data_t* data = (attestation_data_t*)objectP->userData;
    size_t token_size;

    memset(data->nonce,0x00,32);

    for(int i=0,j=0;i<32;i++,j=j+2){
        unsigned char a;
        unsigned char b;
        if (isnum(dataArray->value.asBuffer.buffer[j]))
            a = (dataArray->value.asBuffer.buffer[j] - 0x30);
        else
            a =(dataArray->value.asBuffer.buffer[j] - 55);

        if (isnum(dataArray->value.asBuffer.buffer[j+1]))
            b = (dataArray->value.asBuffer.buffer[j+1] - 0x30);
        else
            b =(dataArray->value.asBuffer.buffer[j+1] - 55);
        
        data->nonce[i] = (a << 4) | b ;
    } 

    data->token = lwm2m_malloc(4096);
    token_size = generate_token(data->nonce,&data->token);
    data->token_size = token_size;
    
    return COAP_204_CHANGED;
}


static uint8_t prv_attestation_read(lwm2m_context_t *contextP,
                        uint16_t objInstId,
                        int * numDataP,
                        lwm2m_data_t** tlvArrayP,
                        lwm2m_object_t * objectP)
{
    int     i;
    uint8_t result = COAP_500_INTERNAL_SERVER_ERROR;
    attestation_data_t* attDataP = (attestation_data_t*)(objectP->userData);

    /* unused parameter */
    (void)contextP;

    // defined as single instance object!
    if (objInstId != 0) return COAP_404_NOT_FOUND;

    if (*numDataP == 0)     // full object, readable resources!
    {
        uint16_t readResIds[] = {
                RES_M_TOKEN                
        }; // readable resources!
        
        *numDataP  = sizeof(readResIds)/sizeof(uint16_t);
        *tlvArrayP = lwm2m_data_new(*numDataP);
        if (*tlvArrayP == NULL) return COAP_500_INTERNAL_SERVER_ERROR;
        
        // init readable resource id's
        for (i = 0 ; i < *numDataP ; i++)
        {
            (*tlvArrayP)[i].id = readResIds[i];
        }
    }
    
    for (i = 0 ; i < *numDataP ; i++)
    {
        if ((*tlvArrayP)[i].type == LWM2M_TYPE_MULTIPLE_RESOURCE)
        {
            result = COAP_404_NOT_FOUND;
        }
        else
        {
            result = prv_res2tlv((*tlvArrayP)+i, attDataP);
        }
        if (result!=COAP_205_CONTENT) break;
    }
    
    return result;
}


void display_attestation_object(lwm2m_object_t * object)
{
    //TODO
}


lwm2m_object_t * get_attestation_object(void)
{
    lwm2m_object_t * attestationObj;

    attestationObj = (lwm2m_object_t *)lwm2m_malloc(sizeof(lwm2m_object_t));
    if (NULL != attestationObj)
    {
        memset(attestationObj, 0, sizeof(lwm2m_object_t));

        // It assigns its unique ID
        attestationObj->objID = ATTESTATION_OBJECT_ID;
        
        // and its unique instance
        attestationObj->instanceList = (lwm2m_list_t *)lwm2m_malloc(sizeof(lwm2m_list_t));
        if (NULL != attestationObj->instanceList)
        {
            memset(attestationObj->instanceList, 0, sizeof(lwm2m_list_t));
        }
        else
        {
            lwm2m_free(attestationObj);
            return NULL;
        }

      
        attestationObj->readFunc    = prv_attestation_read;
        attestationObj->userData    = lwm2m_malloc(sizeof(attestation_data_t));
        attestationObj->writeFunc   = prv_nonce_write;

        // initialize private data structure containing the needed variables
        if (NULL != attestationObj->userData)
        {
            attestation_data_t* data = (attestation_data_t*)attestationObj->userData;
            data->token = NULL;
            data->token_size = 0;
        }
        else
        {
            lwm2m_free(attestationObj);
            attestationObj = NULL;
        }
    }
    
    return attestationObj;
}

void free_attestation_object(lwm2m_object_t * object)
{
    lwm2m_list_free(object->instanceList);
    lwm2m_free(object->userData);
    lwm2m_free(object);
}

