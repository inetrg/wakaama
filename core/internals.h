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
 *    Fabien Fleutot - Please refer to git log
 *    Toby Jaffey - Please refer to git log
 *    Bosch Software Innovations GmbH - Please refer to git log
 *    Pascal Rieux - Please refer to git log
 *    Scott Bertin - Please refer to git log
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

#ifndef _LWM2M_INTERNALS_H_
#define _LWM2M_INTERNALS_H_

#include "liblwm2m.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "er-coap-13.h"

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define LWM2M_LITTLE_ENDIAN
#else
#define LWM2M_BIG_ENDIAN
#endif

#ifdef LWM2M_WITH_LOGS
#include <inttypes.h>
#include "fmt.h"
#define LOG(STR) lwm2m_printf("[%s:%d] " STR "\r\n", __func__ , __LINE__)
#define LOG_ARG(FMT, ...) lwm2m_printf("[%s:%d] " FMT "\r\n", __func__ , __LINE__ , __VA_ARGS__)
/* Log a single value. Use this for 64-bits numbers */
#define LOG_VALUE(FMT, VALUE)                                                       \
{                                                                                   \
    if (!strcmp(FMT, "%"PRId64))                                                    \
    {                                                                               \
        char int64_str[20];                                                         \
        int64_str[fmt_s64_dec(int64_str, (VALUE))] = '\0';                          \
        lwm2m_printf("[%s:%d] %s \r\n", __func__ , __LINE__ , int64_str);           \
    }                                                                               \
    else lwm2m_printf("[%s:%d] " FMT "\r\n", __func__ , __LINE__ , (VALUE));        \
}
#define LOG_URI(URI)                                                                \
{                                                                                   \
    if ((URI) == NULL) lwm2m_printf("[%s:%d] NULL\r\n", __func__ , __LINE__);     \
    else                                                                            \
    {                                                                               \
        lwm2m_printf("[%s:%d] /%d", __func__ , __LINE__ , (URI)->objectId);       \
        if (LWM2M_URI_IS_SET_INSTANCE(URI)) lwm2m_printf("/%d", (URI)->instanceId); \
        if (LWM2M_URI_IS_SET_RESOURCE(URI)) lwm2m_printf("/%d", (URI)->resourceId); \
        lwm2m_printf("\r\n");                                                       \
    }                                                                               \
}
#define STR_STATUS(S)                                           \
((S) == STATE_DEREGISTERED ? "STATE_DEREGISTERED" :             \
((S) == STATE_REG_PENDING ? "STATE_REG_PENDING" :               \
((S) == STATE_REGISTERED ? "STATE_REGISTERED" :                 \
((S) == STATE_REG_FAILED ? "STATE_REG_FAILED" :                 \
((S) == STATE_REG_UPDATE_PENDING ? "STATE_REG_UPDATE_PENDING" : \
((S) == STATE_REG_UPDATE_NEEDED ? "STATE_REG_UPDATE_NEEDED" :   \
((S) == STATE_REG_FULL_UPDATE_NEEDED ? "STATE_REG_FULL_UPDATE_NEEDED" :   \
((S) == STATE_DEREG_PENDING ? "STATE_DEREG_PENDING" :           \
((S) == STATE_BS_HOLD_OFF ? "STATE_BS_HOLD_OFF" :               \
((S) == STATE_BS_INITIATED ? "STATE_BS_INITIATED" :             \
((S) == STATE_BS_PENDING ? "STATE_BS_PENDING" :                 \
((S) == STATE_BS_FINISHED ? "STATE_BS_FINISHED" :               \
((S) == STATE_BS_FINISHING ? "STATE_BS_FINISHING" :             \
((S) == STATE_BS_FAILING ? "STATE_BS_FAILING" :                 \
((S) == STATE_BS_FAILED ? "STATE_BS_FAILED" :                   \
"Unknown")))))))))))))))
#define STR_MEDIA_TYPE(M)                                \
((M) == LWM2M_CONTENT_TEXT ? "LWM2M_CONTENT_TEXT" :      \
((M) == LWM2M_CONTENT_LINK ? "LWM2M_CONTENT_LINK" :      \
((M) == LWM2M_CONTENT_OPAQUE ? "LWM2M_CONTENT_OPAQUE" :  \
((M) == LWM2M_CONTENT_TLV ? "LWM2M_CONTENT_TLV" :        \
((M) == LWM2M_CONTENT_JSON ? "LWM2M_CONTENT_JSON" :      \
"Unknown")))))
#define STR_STATE(S)                                \
((S) == STATE_INITIAL ? "STATE_INITIAL" :      \
((S) == STATE_BOOTSTRAP_REQUIRED ? "STATE_BOOTSTRAP_REQUIRED" :      \
((S) == STATE_BOOTSTRAPPING ? "STATE_BOOTSTRAPPING" :  \
((S) == STATE_REGISTER_REQUIRED ? "STATE_REGISTER_REQUIRED" :        \
((S) == STATE_REGISTERING ? "STATE_REGISTERING" :      \
((S) == STATE_READY ? "STATE_READY" :      \
"Unknown"))))))
#else
#define LOG_ARG(FMT, ...)
#define LOG(STR)
#define LOG_VALUE(FMT, VALUE)
#define LOG_URI(URI)
#endif

#define LWM2M_DEFAULT_LIFETIME  86400

#ifdef LWM2M_SUPPORT_JSON
#define REG_LWM2M_RESOURCE_TYPE     ">;rt=\"oma.lwm2m\";ct=11543,"
#define REG_LWM2M_RESOURCE_TYPE_LEN 25
#else
#define REG_LWM2M_RESOURCE_TYPE     ">;rt=\"oma.lwm2m\","
#define REG_LWM2M_RESOURCE_TYPE_LEN 17
#endif
#define REG_START           "<"
#define REG_DEFAULT_PATH    "/"

#define REG_OBJECT_MIN_LEN  5   // "</n>,"
#define REG_PATH_END        ">,"
#define REG_PATH_SEPARATOR  "/"

#define REG_OBJECT_PATH             "<%s/%hu>,"
#define REG_OBJECT_INSTANCE_PATH    "<%s/%hu/%hu>,"

#define URI_REGISTRATION_SEGMENT        "rd"
#define URI_REGISTRATION_SEGMENT_LEN    2
#define URI_BOOTSTRAP_SEGMENT           "bs"
#define URI_BOOTSTRAP_SEGMENT_LEN       2
#define URI_AUTH_REQUEST_SEGMENT        "ac"
#define URI_AUTH_REQUEST_SEGMENT_LEN    2

#define QUERY_STARTER       "?"
#define QUERY_STARTER_LEN   1
#define QUERY_NAME          "ep="
#define QUERY_NAME_LEN      3       // strlen("ep=")
#define QUERY_SMS           "sms="
#define QUERY_SMS_LEN       4
#define QUERY_LIFETIME      "lt="
#define QUERY_LIFETIME_LEN  3
#define QUERY_VERSION       "lwm2m="
#define QUERY_VERSION_LEN   6
#define QUERY_BINDING       "b="
#define QUERY_BINDING_LEN   2
#define QUERY_DELIMITER     "&"
#define QUERY_DELIMITER_LEN 1

#define LWM2M_VERSION      "1.0"
#define LWM2M_VERSION_LEN  3

#define QUERY_VERSION_FULL      QUERY_VERSION LWM2M_VERSION
#define QUERY_VERSION_FULL_LEN  QUERY_VERSION_LEN+LWM2M_VERSION_LEN

#define REG_URI_START       '<'
#define REG_URI_END         '>'
#define REG_DELIMITER       ','
#define REG_ATTR_SEPARATOR  ';'
#define REG_ATTR_EQUALS     '='
#define REG_ATTR_TYPE_KEY           "rt"
#define REG_ATTR_TYPE_KEY_LEN       2
#define REG_ATTR_TYPE_VALUE         "\"oma.lwm2m\""
#define REG_ATTR_TYPE_VALUE_LEN     11
#define REG_ATTR_CONTENT_KEY        "ct"
#define REG_ATTR_CONTENT_KEY_LEN    2
#define REG_ATTR_CONTENT_JSON       "11543"   // Temporary value
#define REG_ATTR_CONTENT_JSON_LEN   5

#define ATTR_SERVER_ID_STR       "ep="
#define ATTR_SERVER_ID_LEN       3
#define ATTR_MIN_PERIOD_STR      "pmin="
#define ATTR_MIN_PERIOD_LEN      5
#define ATTR_MAX_PERIOD_STR      "pmax="
#define ATTR_MAX_PERIOD_LEN      5
#define ATTR_GREATER_THAN_STR    "gt="
#define ATTR_GREATER_THAN_LEN    3
#define ATTR_LESS_THAN_STR       "lt="
#define ATTR_LESS_THAN_LEN       3
#define ATTR_STEP_STR            "st="
#define ATTR_STEP_LEN            3
#define ATTR_DIMENSION_STR       "dim="
#define ATTR_DIMENSION_LEN       4

#define URI_MAX_STRING_LEN    18      // /65535/65535/65535
#define _PRV_64BIT_BUFFER_SIZE 8

#define LINK_ITEM_START             "<"
#define LINK_ITEM_START_SIZE        1
#define LINK_ITEM_END               ">,"
#define LINK_ITEM_END_SIZE          2
#define LINK_ITEM_DIM_START         ">;dim="
#define LINK_ITEM_DIM_START_SIZE    6
#define LINK_ITEM_ATTR_END          ","
#define LINK_ITEM_ATTR_END_SIZE     1
#define LINK_URI_SEPARATOR          "/"
#define LINK_URI_SEPARATOR_SIZE     1
#define LINK_ATTR_SEPARATOR         ";"
#define LINK_ATTR_SEPARATOR_SIZE    1

#define ATTR_FLAG_NUMERIC (uint8_t)(LWM2M_ATTR_FLAG_LESS_THAN | LWM2M_ATTR_FLAG_GREATER_THAN | LWM2M_ATTR_FLAG_STEP)

#define LWM2M_URI_FLAG_DM           (uint8_t)0x00
#define LWM2M_URI_FLAG_DELETE_ALL   (uint8_t)0x10
#define LWM2M_URI_FLAG_REGISTRATION (uint8_t)0x20
#define LWM2M_URI_FLAG_BOOTSTRAP    (uint8_t)0x40

#define LWM2M_URI_MASK_TYPE (uint8_t)0x70
#define LWM2M_URI_MASK_ID   (uint8_t)0x07

typedef struct
{
    uint16_t clientID;
    lwm2m_uri_t uri;
    lwm2m_result_callback_t callback;
    void * userData;
} dm_data_t;

typedef enum
{
    URI_DEPTH_OBJECT,
    URI_DEPTH_OBJECT_INSTANCE,
    URI_DEPTH_RESOURCE,
    URI_DEPTH_RESOURCE_INSTANCE
} uri_depth_t;

#ifdef LWM2M_BOOTSTRAP_SERVER_MODE
typedef struct
{
    bool        isUri;
    lwm2m_uri_t uri;
    lwm2m_bootstrap_callback_t callback;
    void *      userData;
} bs_data_t;
#endif

// defined in uri.c
lwm2m_uri_t * uri_decode(char * altPath, multi_option_t *uriPath);
int uri_getNumber(uint8_t * uriString, size_t uriLength);
int uri_toString(lwm2m_uri_t * uriP, uint8_t * buffer, size_t bufferLen, uri_depth_t * depthP);

// defined in objects.c
uint8_t object_readData(lwm2m_context_t * contextP, lwm2m_uri_t * uriP, int * sizeP, lwm2m_data_t ** dataP);
uint8_t object_read(lwm2m_context_t * contextP, lwm2m_uri_t * uriP, lwm2m_media_type_t * formatP, uint8_t ** bufferP, size_t * lengthP);
uint8_t object_write(lwm2m_context_t * contextP, lwm2m_uri_t * uriP, lwm2m_media_type_t format, uint8_t * buffer, size_t length);
uint8_t object_create(lwm2m_context_t * contextP, lwm2m_uri_t * uriP, lwm2m_media_type_t format, uint8_t * buffer, size_t length);
uint8_t object_execute(lwm2m_context_t * contextP, lwm2m_uri_t * uriP, uint8_t * buffer, size_t length);
uint8_t object_delete(lwm2m_context_t * contextP, lwm2m_uri_t * uriP);
uint8_t object_discover(lwm2m_context_t * contextP, lwm2m_uri_t * uriP, lwm2m_peer_t * serverP, uint8_t ** bufferP, size_t * lengthP);
uint8_t object_checkReadable(lwm2m_context_t * contextP, lwm2m_uri_t * uriP, lwm2m_attributes_t * attrP);
bool object_isInstanceNew(lwm2m_context_t * contextP, uint16_t objectId, uint16_t instanceId);
int object_getRegisterPayloadBufferLength(lwm2m_context_t * contextP);
int object_getRegisterPayload(lwm2m_context_t * contextP, uint8_t * buffer, size_t length);
int object_getServers(lwm2m_context_t * contextP, bool checkOnly);

int object_getClients(lwm2m_context_t *contextP, bool checkOnly);

bool lwm2m_c2c_handle_notify(lwm2m_context_t * context, void *session, coap_packet_t *message,
                             coap_packet_t * response);

void lwm2m_build_server_hint_response(lwm2m_context_t *context, const lwm2m_uri_t *uri,
                                      coap_packet_t *response);

uint8_t object_createInstance(lwm2m_context_t * contextP, lwm2m_uri_t * uriP, lwm2m_data_t * dataP);
uint8_t object_writeInstance(lwm2m_context_t * contextP, lwm2m_uri_t * uriP, lwm2m_data_t * dataP);

// defined in transaction.c
lwm2m_transaction_t * transaction_new(void * sessionH, coap_method_t method, char * altPath, lwm2m_uri_t * uriP, uint16_t mID, uint8_t token_len, uint8_t* token);
int transaction_send(lwm2m_context_t * contextP, lwm2m_transaction_t * transacP);
void transaction_free(lwm2m_transaction_t * transacP);
void transaction_remove(lwm2m_context_t * contextP, lwm2m_transaction_t * transacP);
bool transaction_handleResponse(lwm2m_context_t * contextP, void * fromSessionH, coap_packet_t * message, coap_packet_t * response);
void transaction_step(lwm2m_context_t * contextP, time_t currentTime, time_t * timeoutP);

// defined in management.c
uint8_t dm_handleRequest(lwm2m_context_t * contextP, lwm2m_uri_t * uriP, lwm2m_peer_t * serverP, coap_packet_t * message, coap_packet_t * response);

// defined in client_to_client.c
uint8_t client_handleRequest(lwm2m_context_t *context, lwm2m_uri_t *uri, lwm2m_peer_t *client, coap_packet_t *message, coap_packet_t *response);

// defined in observe.c
uint8_t observe_handleRequest(lwm2m_context_t * contextP, lwm2m_uri_t * uriP, lwm2m_peer_t * serverP, int size, lwm2m_data_t * dataP, coap_packet_t * message, coap_packet_t * response);
uint8_t observe_handleClientRequest(lwm2m_context_t *context, lwm2m_uri_t *uri,
                                    lwm2m_peer_t *client, int size, lwm2m_data_t *data,
                                    coap_packet_t *message, coap_packet_t *response);
void observe_cancel(lwm2m_context_t * contextP, uint16_t mid, void * fromSessionH);
uint8_t observe_setParameters(lwm2m_context_t * contextP, lwm2m_uri_t * uriP, lwm2m_peer_t * serverP, lwm2m_attributes_t * attrP);
void observe_step(lwm2m_context_t * contextP, time_t currentTime, time_t * timeoutP);
void observe_clear(lwm2m_context_t * contextP, lwm2m_uri_t * uriP);
bool observe_handleNotify(lwm2m_context_t * contextP, void * fromSessionH, coap_packet_t * message, coap_packet_t * response);
void observe_remove(lwm2m_observation_t * observationP);
lwm2m_observed_t * observe_findByUri(lwm2m_context_t * contextP, lwm2m_uri_t * uriP);

// defined in registration.c
uint8_t registration_handleRequest(lwm2m_context_t * contextP, lwm2m_uri_t * uriP, void * fromSessionH, coap_packet_t * message, coap_packet_t * response);
void registration_deregister(lwm2m_context_t * contextP, lwm2m_peer_t * serverP);
void registration_freeClient(lwm2m_client_t * clientP);
uint8_t registration_start(lwm2m_context_t * contextP);
void registration_step(lwm2m_context_t * contextP, time_t currentTime, time_t * timeoutP);
lwm2m_status_t registration_getStatus(lwm2m_context_t * contextP);

// defined in packet.c
uint8_t message_send(lwm2m_context_t * contextP, coap_packet_t * message, void * sessionH);

// defined in bootstrap.c
void bootstrap_step(lwm2m_context_t * contextP, time_t currentTime, time_t* timeoutP);
uint8_t bootstrap_handleCommand(lwm2m_context_t * contextP, lwm2m_uri_t * uriP, lwm2m_peer_t * serverP, coap_packet_t * message, coap_packet_t * response);
uint8_t bootstrap_handleDeleteAll(lwm2m_context_t * context, void * fromSessionH);
uint8_t bootstrap_handleFinish(lwm2m_context_t * context, void * fromSessionH);
uint8_t bootstrap_handleRequest(lwm2m_context_t * contextP, lwm2m_uri_t * uriP, void * fromSessionH, coap_packet_t * message, coap_packet_t * response);
void bootstrap_start(lwm2m_context_t * contextP);
lwm2m_status_t bootstrap_getStatus(lwm2m_context_t * contextP);

// defined in tlv.c
int tlv_parse(uint8_t * buffer, size_t bufferLen, lwm2m_data_t ** dataP);
int tlv_serialize(bool isResourceInstance, int size, lwm2m_data_t * dataP, uint8_t ** bufferP);

// defined in json.c
#ifdef LWM2M_SUPPORT_JSON
int json_parse(lwm2m_uri_t * uriP, uint8_t * buffer, size_t bufferLen, lwm2m_data_t ** dataP);
int json_serialize(lwm2m_uri_t * uriP, int size, lwm2m_data_t * tlvP, uint8_t ** bufferP);
#endif

// defined in discover.c
int discover_serialize(lwm2m_context_t * contextP, lwm2m_uri_t * uriP, lwm2m_peer_t * serverP, int size, lwm2m_data_t * dataP, uint8_t ** bufferP);

// defined in block1.c
uint8_t coap_block1_handler(lwm2m_block1_data_t ** block1Data, uint16_t mid, uint8_t * buffer, size_t length, uint16_t blockSize, uint32_t blockNum, bool blockMore, uint8_t ** outputBuffer, size_t * outputLength);
void free_block1_buffer(lwm2m_block1_data_t * block1Data);

// defined in utils.c
lwm2m_data_type_t utils_depthToDatatype(uri_depth_t depth);
lwm2m_binding_t utils_stringToBinding(uint8_t *buffer, size_t length);
lwm2m_media_type_t utils_convertMediaType(coap_content_type_t type);
int utils_isAltPathValid(const char * altPath);
int utils_stringCopy(char * buffer, size_t length, const char * str);
size_t utils_intToText(int64_t data, uint8_t * string, size_t length);
size_t utils_floatToText(double data, uint8_t * string, size_t length);
int utils_textToInt(uint8_t * buffer, int length, int64_t * dataP);
int utils_textToFloat(uint8_t * buffer, int length, double * dataP);
void utils_copyValue(void * dst, const void * src, size_t len);
size_t utils_base64GetSize(size_t dataLen);
size_t utils_base64Encode(uint8_t * dataP, size_t dataLen, uint8_t * bufferP, size_t bufferLen);
#ifdef LWM2M_CLIENT_MODE
lwm2m_peer_t * utils_findServer(lwm2m_context_t * contextP, void * fromSessionH);

lwm2m_peer_t * utils_findClient(lwm2m_context_t * contextP, void * fromSessionH);

lwm2m_peer_t * utils_findBootstrapServer(lwm2m_context_t * contextP, void * fromSessionH);
#endif

#endif

/**
 * @def         IS_ACTIVE(macro)
 * @brief       Allows to verify a macro definition outside the preprocessor.
 *
 * @details     This macro is based on Linux's clever 'IS_BUILTIN'
 *              (https://github.com/torvalds/linux/blob/master/include/linux/kconfig.h).
 *              It takes a @p macro value that may be defined to 1 or not even
 *              defined (e.g. FEATURE_FOO) and then expands it to an expression
 *              that can be used in C code, either 1 or 0.
 *
 *              The advantage of using this is that the compiler sees all the
 *              code, so checks can be performed, sections that would not be
 *              executed are removed during optimization. For example:
 * ```
 * if (IS_ACTIVE(FEATURE_FOO)) {
 *      do_something();
 * }
 * ```
 * @param[in]   macro   Macro to evaluate
 * @returns     1 if the macro is defined to 1
 * @returns     0 if the macro is not defined, of if it is defined to something
 *              else than 1.
 *
 * @note        This should only be used when macros are defined as 1, it will
 *              not work if the macro value is, for example, (1) or 1U.
 *
 * @note        Although this may seem to work similarly to the preprocessor's
 *              'defined', it is not entirely equal. If the given macro has
 *              been defined with no value, this will expand to 0. Also note
 *              that this is intended to be used with 'boolean' macros that act
 *              as switches, and usually will be defined as 1 or not defined.
 */
#define IS_ACTIVE(macro) __is_active(macro)

/* Here a prefix "__PREFIX_WHEN_" is added to the macro. So if it was a 1 we
 * have "__PREFIX_WHEN_1", and if it was not defined we have "__PREFIX_WHEN_".
 */
#define __is_active(val)              ___is_active(__PREFIX_WHEN_##val)

/* With this placeholder we turn the original value into two arguments when the
 * original value was defined as 1 (note the comma).
 */
#define __PREFIX_WHEN_1 0,

/* Here we add two extra arguments, that way the next macro can accept varargs.
 *
 * If the original macro was defined as 1, this will have three arguments
 * (__take_second_arg(0, 1, 0, 0)), otherwise it will have two
 * (__take_second_arg(__PREFIX_WHEN_ 1, 0, 0)). The third zero is there just to
 * be compliant with C99, which states that when a function-like macro ends
 * with ellipsis (...) it should be called with at least one argument for the
 * variable list.
 */
#define ___is_active(arg1_or_junk)    __take_second_arg(arg1_or_junk 1, 0, 0)

/* Finally, we just always take the second argument, which will be either 1
 * (when three arguments are passed, i.e. macro was defined as 1) or 0 (when
 * only two arguments are passed).
 */
#define __take_second_arg(__ignored, val, ...) val
