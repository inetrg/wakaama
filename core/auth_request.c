#include "internals.h"
#include "cbor.h"

#define AUTH_REQUEST_HOST_PARAM "ep="

typedef struct {
    lwm2m_peer_t *server;
    char ep[64];
    lwm2m_auth_request_cb_t cb;
    void *user_data;
    lwm2m_context_t *context;
} auth_request_data_t;

static void _auth_request_cb(lwm2m_transaction_t *transaction, void *message)
{
    coap_packet_t * packet = (coap_packet_t *)message;
    auth_request_data_t *data = (auth_request_data_t *)transaction->userData;

    LOG_ARG("Authorization request callback: code %d", packet->code);
    if (data->cb) {
        data->cb(data->server->shortID, packet->code, data->user_data); // TODO: add uri?
    }

    lwm2m_free(data);
}

static int _auth_request(lwm2m_context_t *context, lwm2m_peer_t *server,
                         char *host_ep, size_t host_ep_len,lwm2m_auth_request_t *requests,
                         size_t request_len, lwm2m_auth_request_cb_t cb, void *user_data)
{
    lwm2m_transaction_t *transaction;
    int result = COAP_NO_ERROR;
    char *query;
    int query_len = 0;

    if (host_ep_len > 64) {
        LOG("URI too long");
        result = COAP_400_BAD_REQUEST;
        goto out;
    }

    size_t cbor_buf_len = 6 * request_len + 1;
    uint8_t *cbor_buf = lwm2m_malloc(cbor_buf_len); // TODO: check this
    if (!cbor_buf) {
        LOG("Could not allocate CBOR buffer");
        goto out;
    }

    CborEncoder encoder;
    CborEncoder map_encoder;
    cbor_encoder_init(&encoder, cbor_buf, cbor_buf_len, 0);
    cbor_encoder_create_map(&encoder, &map_encoder, request_len);

    for (unsigned i = 0; i < request_len; i++) {
        CborEncoder array_encoder;
        size_t array_size = 0;

        if (requests[i].uri.flag & LWM2M_URI_FLAG_OBJECT_ID) {
            array_size++;
        }

        if (requests[i].uri.flag & LWM2M_URI_FLAG_INSTANCE_ID) {
            array_size++;
        }

        cbor_encoder_create_array(&map_encoder, &array_encoder, array_size);

        if (requests[i].uri.flag & LWM2M_URI_FLAG_OBJECT_ID) {
            cbor_encode_uint(&array_encoder, requests[i].uri.objectId);
        }

        if (requests[i].uri.flag & LWM2M_URI_FLAG_INSTANCE_ID) {
            cbor_encode_uint(&array_encoder, requests[i].uri.instanceId);
        }

        cbor_encoder_close_container(&map_encoder, &array_encoder);

        cbor_encode_uint(&map_encoder, requests[i].access);
    }

    cbor_encoder_close_container(&encoder, &map_encoder);

    LOG_ARG("Needed %d more bytes", cbor_encoder_get_extra_bytes_needed(&encoder));

    transaction = transaction_new(server->sessionH, COAP_POST, NULL, NULL, context->nextMID++,
                                  4, NULL);
    if (!transaction) {
        LOG("Could not allocate new transaction");
        result = COAP_500_INTERNAL_SERVER_ERROR;
        goto free_cbor_out;
    }

    query_len += strlen(QUERY_STARTER);
    query_len += strlen(AUTH_REQUEST_HOST_PARAM);
    query_len += host_ep_len;

    query = lwm2m_malloc(query_len);
    if (!query) {
        LOG("Could not allocate query");
        result = COAP_500_INTERNAL_SERVER_ERROR;
        goto free_transaction_out;
    }

    query_len = 0;
    strcpy(&query[query_len], QUERY_STARTER);
    query_len += strlen(QUERY_STARTER);
    strcpy(&query[query_len], AUTH_REQUEST_HOST_PARAM);
    query_len += strlen(AUTH_REQUEST_HOST_PARAM);
    strcpy(&query[query_len], host_ep);
    query_len += host_ep_len;

    coap_set_header_uri_path(transaction->message, "/"URI_AUTH_REQUEST_SEGMENT);
    coap_set_header_uri_query(transaction->message, query);
    coap_set_header_content_type(transaction->message, LWM2M_CONTENT_CBOR);
    coap_set_payload(transaction->message, cbor_buf, (size_t)cbor_encoder_get_buffer_size(&encoder, cbor_buf));

    auth_request_data_t *data = lwm2m_malloc(sizeof(auth_request_data_t));
    if (!data) {
        LOG("Could not allocate new data");
        result = COAP_500_INTERNAL_SERVER_ERROR;
        goto free_query_transaction_cbor_out;
    }
    memset(data, 0, sizeof(auth_request_data_t));

    data->cb = cb;
    data->context = context;
    data->server = server;
    data->user_data = user_data;
    memcpy(data->ep, host_ep, host_ep_len);

    transaction->callback = _auth_request_cb;
    transaction->userData = data;

    context->transactionList = (lwm2m_transaction_t *)LWM2M_LIST_ADD(context->transactionList,
                                                                     transaction);
    if (transaction_send(context, transaction) != 0) {
        goto free_out;
    }
    goto out;

free_out:
    lwm2m_free(data);
free_query_transaction_cbor_out:
    lwm2m_free(query);
free_transaction_out:
    lwm2m_free(transaction);
free_cbor_out:
    lwm2m_free(cbor_buf);
out:
    return result;
}

int lwm2m_auth_request(lwm2m_context_t *context, uint16_t short_server_id,
                       char *host_ep, size_t host_ep_len, lwm2m_auth_request_t *requests,
                       size_t requests_len, lwm2m_auth_request_cb_t cb, void *user_data)
{
    lwm2m_peer_t *server;

    LOG("Attempting an authorization request");

    server = context->serverList;
    if (!server) {
        if (object_getServers(context, false) == -1) {
            LOG("No server found");
            return COAP_404_NOT_FOUND;
        }
    }

    // try to find the server
    while (server) {
        if (server->shortID == short_server_id) {
            break;
        }
    }

    if (!server) {
        return COAP_404_NOT_FOUND;
    }

    // found the server, trigger the request
    return _auth_request(context, server, host_ep, host_ep_len, requests, requests_len, cb,
                         user_data);
}

void lwm2m_build_server_hint_response(lwm2m_context_t *context, const lwm2m_uri_t *uri,
                                      coap_packet_t *response)
{
    int owner_id = lwm2m_get_owner(uri, context->userData);

    if (owner_id < 0) {
        LOG("No owner defined for requested resource, using a default one");
        /* use a default server ID even when the owner or resource is not defined */
        owner_id = context->serverList->shortID;
    }

    uint16_t owner_security_instance_id = 0;
    lwm2m_peer_t *peer = context->serverList;
    while (peer) {
        if (peer->shortID == owner_id) {
            owner_security_instance_id = peer->secObjInstID;
            break;
        }
        peer = peer->next;
    }

    if (!peer) {
        LOG_ARG("Can't find server with short ID %d", owner_id);
    }

    lwm2m_uri_t query_uri = {
        .objectId = LWM2M_SECURITY_OBJECT_ID,
        .instanceId = owner_security_instance_id,
        .resourceId = LWM2M_SECURITY_URI_ID,
        .flag = LWM2M_URI_FLAG_OBJECT_ID | LWM2M_URI_FLAG_INSTANCE_ID | LWM2M_URI_FLAG_RESOURCE_ID
    };

    int size = 0;
    lwm2m_data_t *data = NULL;
    int res = object_readData(context, &query_uri, &size, &data);

    if (res != COAP_205_CONTENT) {
        lwm2m_data_free(size, data);
        return;
    }

    size_t cbor_buf_len = 4 + data->value.asBuffer.length;
    uint8_t *cbor_buf = lwm2m_malloc(cbor_buf_len); // TODO: check this
    if (!cbor_buf) {
        LOG("Could not allocate CBOR buffer");
        return;
    }

    CborEncoder encoder;
    CborEncoder map_encoder;
    cbor_encoder_init(&encoder, cbor_buf, cbor_buf_len, 0);
    cbor_encoder_create_map(&encoder, &map_encoder, 1);
    cbor_encode_uint(&map_encoder, 1);
    cbor_encode_text_string(&map_encoder, (char *)data->value.asBuffer.buffer, data->value.asBuffer.length);
    cbor_encoder_close_container(&encoder, &map_encoder);

    coap_set_header_content_type(response, LWM2M_CONTENT_CBOR);
    coap_set_payload(response, cbor_buf, (size_t)cbor_encoder_get_buffer_size(&encoder, cbor_buf));
}

int lwm2m_get_unknown_conn_response(lwm2m_context_t *context, uint8_t *in, int in_len,
                                    uint8_t *out, int out_len)
{
    coap_packet_t message;
    coap_packet_t response;
    int result = -1;

    const coap_status_t coap_code = coap_parse_message(&message, in, in_len);

    if (coap_code != NO_ERROR) {
        LOG("Could not parse CoAP message");
        goto out;
    }

    if (message.code != COAP_GET && message.code != COAP_POST && message.code != COAP_PUT &&
        message.code != COAP_DELETE) {
        LOG_ARG("Ignoring unexpected response, code (%d)", message.code);
        goto out;
    }

    lwm2m_uri_t *uri = uri_decode(context->altPath, message.uri_path);
    if (!uri) {
        LOG("Could not parse URI");
        goto out;
    }

    /* prepare unauthorized response */
    if (message.type == COAP_TYPE_CON) {
        /* Reliable CON requests are answered with an ACK */
        coap_init_message(&response, COAP_TYPE_ACK, COAP_401_UNAUTHORIZED, message.mid);
    }
    else {
        /* Unreliable NON requests are answered with a NON */
        coap_init_message(&response, COAP_TYPE_NON, COAP_401_UNAUTHORIZED, context->nextMID++);
    }

    /* find owner server for the requested resource */
    LOG("Finding owner");
    LOG_URI(uri);
    lwm2m_build_server_hint_response(context, uri, &response);

    /* mirror received token */
    if (message.token_len) {
        coap_set_header_token(&response, message.token, message.token_len);
    }

    int len = coap_serialize_get_size(&response);
    if (!len || len > out_len) {
        LOG_ARG("Response needs %d bytes, output buffer is %d bytes", len, out_len);
        goto free_out;
    }

    result = coap_serialize_message(&response, out);

    if (response.payload) {
        lwm2m_free(response.payload);
    }

free_out:
    coap_free_header(&message);
    coap_free_header(&response);
    lwm2m_free(uri);
out:
    return result;
}
