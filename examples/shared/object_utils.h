#ifndef OBJECT_UTILS_H_
#define OBJECT_UTILS_H_

#include "liblwm2m.h"

#ifdef LWM2M_CLIENT_MODE

// generic helper functions
int object_get_int(lwm2m_context_t *clientCtx, uint16_t objId, uint16_t instanceId, uint16_t resourceId, int *value);
int object_get_str(lwm2m_context_t *clientCtx, uint16_t objId, uint16_t instanceId, uint16_t resourceId, char **value);
int object_get_opaque(lwm2m_context_t *clientCtx, uint16_t objId, uint16_t instanceId, uint16_t resourceId,
                      uint8_t **value, size_t *len);

int security_get_secret_key(lwm2m_context_t *clientCtx, uint16_t securityInstanceId, uint8_t **psk, size_t *len);
int security_get_public_key(lwm2m_context_t *clientCtx, uint16_t securityInstanceId, uint8_t **pskId, size_t *len);
int security_get_server_public_key(lwm2m_context_t *clientCtx, uint16_t securityInstanceId, uint8_t **publicKey, size_t *len);
int security_get_security_mode(lwm2m_context_t *clientCtx, uint16_t securityInstanceId, int *mode);
int security_get_sni(lwm2m_context_t *clientCtx, uint16_t securityInstanceId,uint8_t **sni);

#endif /* LWM2M_CLIENT_MODE */

#endif /* OBJECT_UTILS_H_ */
