#include "internals.h"

/**
 * @brief   Perform a CoAP request to a client @p client.
 *
 * @param[in] context       LwM2M context
 * @param[in] client        Client to perform the request on
 * @param[in] uri           URI to request
 * @param[in] method        CoAP method to use
 * @param[in] format        Media Type to use
 * @param[in] payload       Buffer to include as payload. May be NULL
 * @param[in] payload_len   Length of @p payload
 * @param[in] cb            Callback to get the result
 * @param[in] user_data     Opaque user data
 *
 * @return CoAP response code
 */
static int _request(lwm2m_context_t *context, lwm2m_peer_t *client, lwm2m_uri_t *uri,
                    coap_method_t method, lwm2m_media_type_t format, uint8_t *payload,
                    size_t payload_len, lwm2m_result_callback_t cb, void *user_data);

/**
 * @brief   Callback for all client to client CoAP requests.
 */
static void _result_callback(lwm2m_transaction_t *transaction, void *message);

// #ifdef LWM2M_CLIENT_C2C

void lwm2m_set_client_session(lwm2m_context_t *contextP, void *session,
                              uint16_t client_sec_instance_id)
{
    LOG_ARG("Adding client session for security ID %d", client_sec_instance_id);

    if (!contextP || !session) {
        return;
    }

    lwm2m_peer_t *client;
    client = (lwm2m_peer_t *)LWM2M_LIST_FIND(contextP->clientList, client_sec_instance_id);
    if (client) {
        client->sessionH = session;
    }
    else {
        LOG("ERROR: no such a client in peer list");
    }
}

int lwm2m_c2c_read(lwm2m_context_t *context, uint16_t client_sec_instance_id, lwm2m_uri_t *uri,
                   lwm2m_result_callback_t cb, void *user_data)
{
    lwm2m_peer_t *client;

    LOG_ARG("Reading from client %d", client_sec_instance_id);
    LOG_URI(uri);

    client = (lwm2m_peer_t *)LWM2M_LIST_FIND(context->clientList, client_sec_instance_id);
    if (!client) {
        LOG("No client found");
        return COAP_404_NOT_FOUND;
    }

    return _request(context, client, uri, COAP_GET, LWM2M_CONTENT_TLV, NULL, 0, cb, user_data);
}

static int _request(lwm2m_context_t *context, lwm2m_peer_t *client, lwm2m_uri_t *uri,
                    coap_method_t method, lwm2m_media_type_t format, uint8_t *payload,
                    size_t payload_len, lwm2m_result_callback_t cb, void *user_data)
{
    LOG_ARG("Making a %d request", method);


    /* check if there is already a connection to the client */
    if (!client->sessionH) {
        LOG("Attempting client connection");
        client->sessionH = lwm2m_connect_client(client->secObjInstID, user_data);
    }

    if (!client->sessionH) {
        return COAP_404_NOT_FOUND;
    }

    /* TODO: alternate path? */
    lwm2m_transaction_t *transaction = transaction_new(client->sessionH, method, NULL, uri,
                                                       context->nextMID++, 4, NULL);

    if (!transaction) {
        LOG("Could not create transaction");
        return COAP_500_INTERNAL_SERVER_ERROR;
    }

    if (method == COAP_GET) {
        coap_set_header_accept(transaction->message, format);
    }
    else if (payload) {
        coap_set_header_content_type(transaction->message, format);
        /* TODO: for now ignoring fragmentation */
        coap_set_payload(transaction->message, payload, payload_len);
    }

    if (cb) {
        /* if a callback has been specified, add the info and attach it to the transaction */
        dm_data_t *data = (dm_data_t *)lwm2m_malloc(sizeof(dm_data_t));
        if (!data) {
            LOG("There is a callback but can't allocate a data");
            transaction_free(transaction);
            return COAP_500_INTERNAL_SERVER_ERROR;
        }

        memcpy(&data->uri, uri, sizeof(lwm2m_uri_t));
        data->clientID = client->secObjInstID;
        data->callback = cb;
        data->userData = user_data;

        transaction->callback = _result_callback;
        transaction->userData = data;
    }

    context->transactionList = (lwm2m_transaction_t *)LWM2M_LIST_ADD(context->transactionList,
                                                                     transaction);
    return transaction_send(context, transaction);
}

static void _result_callback(lwm2m_transaction_t *transaction, void *message)
{
    dm_data_t *data = (dm_data_t *)transaction->userData;


    if (!message) {
        LOG("Did not get response");
        data->callback(data->clientID, &data->uri, COAP_503_SERVICE_UNAVAILABLE, LWM2M_CONTENT_TEXT,
                       NULL, 0, data->userData);
        return;
    }

    LOG("Got response");
    if (data->callback) {
        LOG("Calling callback");
        coap_packet_t *pkt = (coap_packet_t *)message;
        data->callback(data->clientID, &data->uri, pkt->code,
                       utils_convertMediaType(pkt->content_type), pkt->payload, pkt->payload_len,
                       data->userData);
    }

    lwm2m_free(data);
}


// int lwm2m_get_client_resource(lwm2m_conext_t *context, uint16_t sec_obj_inst_id,
//                               const lwm2m_uri_t *uri, char *out, size_t out_len)
// {
//     (void) uri;
//     (void) out;
//     (void) out_len;

//     if (!(uri->flag & LWM2M_URI_FLAG_OBJECT_ID) || !(uri->flag & LWM2M_URI_FLAG_INSTANCE_ID) ||
//         !(uri->flag & LWM2M_URI_FLAG_RESOURCE_ID)) {
//         DEBUG("[lwm2m_get_client_resource] URI should point to a resource\n");
//         return -1;
//     }

//     /* check if there is an existing connection to the client */
//     lwm2m_client_connection_t *conn = client_data->client_conn_list;

//     while (conn) {
//         if (sec_obj_inst_id == conn->sec_inst_id) {
//             break;
//         }
//         conn = conn->next;
//     }

//     if (!conn) {
//         DEBUG("[lwm2m_get_client_resource] no existent connection, creating one\n");
//         /* create a new connection */
//         conn = (lwm2m_client_connection_t *)lwm2m_connect_client(sec_obj_inst_id, client_data);

//         /* add new connection (session) */
//         lwm2m_set_client_session(client_data->lwm2m_ctx, conn, sec_obj_inst_id);
//     }

//     if (!conn) {
//         DEBUG("[lwm2m_get_client_resource] could not establish connection to %d\n", sec_obj_inst_id);
//         return -1;
//     }

//     return -1;
// }

// #endif
