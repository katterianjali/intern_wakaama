#ifndef MBEDTLSCONNECTION_H_
#define MBEDTLSCONNECTION_H_

#include "liblwm2m.h"

int * mbedtls_get_sockets(lwm2m_context_t const * ctx, int * sz);

int mbedtls_receive(lwm2m_context_t const * ctx, int sock, uint8_t * buffer, int sz, void ** connection);



#endif