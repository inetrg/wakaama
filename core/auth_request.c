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
