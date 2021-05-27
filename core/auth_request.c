#include "internals.h"

#define AUTH_REQUEST_HOST_PARAM "h="

typedef struct {
    lwm2m_peer_t *server;
    char uri[64];
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
                         char *host_uri, size_t host_uri_len,
                         lwm2m_auth_request_cb_t cb, void *user_data)
{
    lwm2m_transaction_t *transaction;
    int result = COAP_NO_ERROR;
    char *query;
    int query_len = 0;

    if (host_uri_len > 64) {
        LOG("URI too long");
        result = COAP_400_BAD_REQUEST;
        goto out;
    }

    transaction = transaction_new(server->sessionH, COAP_POST, NULL, NULL, context->nextMID++,
                                  4, NULL);
    if (!transaction) {
        LOG("Could not allocate new transaction");
        result = COAP_500_INTERNAL_SERVER_ERROR;
        goto out;
    }

    query_len += strlen(QUERY_STARTER);
    query_len += strlen(AUTH_REQUEST_HOST_PARAM);
    query_len += host_uri_len;

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
    strcpy(&query[query_len], host_uri);
    query_len += host_uri_len;

    coap_set_header_uri_path(transaction->message, "/"URI_AUTH_REQUEST_SEGMENT);
    coap_set_header_uri_query(transaction->message, query);

    auth_request_data_t *data = lwm2m_malloc(sizeof(auth_request_data_t));
    if (!data) {
        LOG("Could not allocate new data");
        result = COAP_500_INTERNAL_SERVER_ERROR;
        goto free_query_transaction_out;
    }
    memset(data, 0, sizeof(auth_request_data_t));

    data->cb = cb;
    data->context = context;
    data->server = server;
    data->user_data = user_data;
    memcpy(data->uri, host_uri, host_uri_len);

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
free_query_transaction_out:
    lwm2m_free(query);
free_transaction_out:
    lwm2m_free(transaction);
out:
    return result;
}

int lwm2m_auth_request(lwm2m_context_t *context, uint16_t short_server_id,
                       char *host_uri, size_t host_uri_len,
                       lwm2m_auth_request_cb_t cb, void *user_data) {

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
    return _auth_request(context, server, host_uri, host_uri_len, cb, user_data);
}
