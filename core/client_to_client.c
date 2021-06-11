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

/**
 * @brief   Callback for observe client to client requests.
 */
static void _observe_callback(lwm2m_transaction_t *transaction, void *message);

/**
 * @brief   Check for an existing observation that matches the URI in a given peer.
 *
 * @return Observation that matches the URI
 * @retval NULL if no observation is found
 */
static lwm2m_peer_observation_t *_find_peer_observation(lwm2m_peer_t *peer, lwm2m_uri_t *uri);

typedef struct {
    uint16_t                sec_inst_id;
    uint16_t                id;
    lwm2m_uri_t             uri;
    lwm2m_result_callback_t callback;
    void *                  user_data;
    lwm2m_context_t *       context;
} c2c_observation_data_t;


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

void lwm2m_remove_client_session(lwm2m_context_t *context, uint16_t secObjInstID)
{
    LOG_ARG("Closing client connection with security ID %d", secObjInstID);

    if (!context) {
        LOG("No context!");
        return;
    }

    lwm2m_peer_t *client;
    client = (lwm2m_peer_t *)LWM2M_LIST_FIND(context->clientList, secObjInstID);
    if (client && client->sessionH) {
        lwm2m_close_client_connection(client->sessionH, context->userData);
        client->sessionH = NULL;
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

int lwm2m_c2c_observe(lwm2m_context_t *context, uint16_t client_sec_instance_id, lwm2m_uri_t *uri,
                      lwm2m_result_callback_t cb, void *user_data)
{
    lwm2m_peer_t *client = NULL;
    lwm2m_peer_observation_t *obs = NULL;
    c2c_observation_data_t *obs_data = NULL;
    lwm2m_transaction_t *transaction = NULL;
    uint8_t token[4];

    LOG_ARG("Observing resource in client %d", client_sec_instance_id);
    LOG_URI(uri);

    client = (lwm2m_peer_t *)LWM2M_LIST_FIND(context->clientList, client_sec_instance_id);
    if (!client) {
        LOG("No client found");
        return COAP_404_NOT_FOUND;
    }

    /* check if there is already a connection to the client */
    if (!client->sessionH) {
        LOG("Attempting client connection");
        client->sessionH = lwm2m_connect_client(client->secObjInstID, user_data);
    }

    if (!client->sessionH) {
        return COAP_404_NOT_FOUND;
    }

    obs_data = (c2c_observation_data_t *)lwm2m_malloc(sizeof(c2c_observation_data_t));
    if (!obs_data) {
        LOG("Could not instantiate the observation data structure");
        return COAP_500_INTERNAL_SERVER_ERROR;
    }
    memset(obs_data, 0, sizeof(c2c_observation_data_t));

    obs_data->id = ++client->observationId;

    /* observationId may overflow. ensure new ID is not already present */
    if(LWM2M_LIST_FIND(client->observationList, obs_data->id)) {
        LOG("Can't get available observation ID. Request failed.\n");
        lwm2m_free(obs_data);
        return COAP_500_INTERNAL_SERVER_ERROR;
    }

    memcpy(&obs_data->uri, uri, sizeof(lwm2m_uri_t));
    obs_data->id = client->secObjInstID;
    obs_data->callback = cb;
    obs_data->user_data = user_data;
    obs_data->context = context;

    token[0] = client->secObjInstID >> 8;
    token[1] = client->secObjInstID & 0xFF;
    token[2] = obs_data->id >> 8;
    token[3] = obs_data->id & 0xFF;

    /* TODO: alternate path? */
    transaction = transaction_new(client->sessionH, COAP_GET, NULL, uri, context->nextMID++, 4,
                                  token);
    if (!transaction) {
        LOG("Could not create a new transaction");
        lwm2m_free(obs_data);
        return COAP_500_INTERNAL_SERVER_ERROR;
    }

    coap_set_header_observe(transaction->message, 0);
    coap_set_header_accept(transaction->message, LWM2M_CONTENT_TLV);

    transaction->callback = _observe_callback;
    transaction->userData = obs_data;

    context->transactionList = (lwm2m_transaction_t *)LWM2M_LIST_ADD(context->transactionList,
                                                                     transaction);

    obs = _find_peer_observation(client, uri);
    if (obs) {
        obs->status = STATE_REG_PENDING;
    }

    int res = transaction_send(context, transaction);
    if (res != 0)     {
        LOG("transaction_send failed!");
        lwm2m_free(obs_data);
    }
    return res;
}

bool lwm2m_c2c_handle_notify(lwm2m_context_t * context, void *session, coap_packet_t *message,
                             coap_packet_t * response)
{
    const uint8_t *token;
    int token_len;
    uint16_t client_id;
    uint16_t obs_id;
    lwm2m_peer_t *client;
    lwm2m_peer_observation_t *obs;
    uint32_t count;

    LOG("Entering");

    token_len = coap_get_header_token(message, &token);
    if (token_len != sizeof(uint32_t)){
        return false;
    }

    if (coap_get_header_observe(message, &count) != 1){
        return false;
    }

    client_id = (token[0] << 8) | token[1];
    obs_id = (token[2] << 8) | token[3];

    client = (lwm2m_peer_t *)LWM2M_LIST_FIND(context->clientList, client_id);
    if (!client) {
        LOG_ARG("Unknown client id %d", client_id);
        return false;
    }

    obs = (lwm2m_peer_observation_t *)LWM2M_LIST_FIND(client->observationList, obs_id);
    if (!obs) {
        LOG("Unexpected notification, cancel that"); /* go away */
        coap_init_message(response, COAP_TYPE_RST, 0, message->mid);
        message_send(context, response, session);
        return true;
    }

    /* reply if confirmation is needed */
    if (message->type == COAP_TYPE_CON ) {
        coap_init_message(response, COAP_TYPE_ACK, 0, message->mid);
        message_send(context, response, session);
    }

    /* call the registered user callback */
    obs->callback(client_id, &obs->uri, (int)count, utils_convertMediaType(message->content_type),
                  message->payload, message->payload_len, obs->user_data);

    return true;
}

static lwm2m_peer_observation_t *_find_peer_observation(lwm2m_peer_t *peer, lwm2m_uri_t *uri)
{
    lwm2m_peer_observation_t *obs = peer->observationList;

    while (obs) {
        if (obs->uri.objectId == uri->objectId && obs->uri.flag == uri->flag &&
            obs->uri.instanceId == uri->instanceId && obs->uri.resourceId == uri->resourceId)
        {
            return obs;
        }

        obs = obs->next;
    }

    return obs;
}

static int _request(lwm2m_context_t *context, lwm2m_peer_t *client, lwm2m_uri_t *uri,
                    coap_method_t method, lwm2m_media_type_t format, uint8_t *payload,
                    size_t payload_len, lwm2m_result_callback_t cb, void *user_data)
{
    LOG_ARG("Making a %d request", method);
    bool first_request = false;

    /* check if there is already a connection to the client */
    if (!client->sessionH) {
        LOG("Attempting client connection");
        client->sessionH = lwm2m_connect_client(client->secObjInstID, user_data);
        first_request = true;
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

    char *query = NULL;
    if (first_request) {
        /* we must include the endpoint name */
        int query_len = strlen(QUERY_STARTER);
        query_len += QUERY_NAME_LEN;
        query_len += strlen(context->endpointName) + 1;

        query = lwm2m_malloc(query_len);
        if (query) {
            query_len = 0;
            strcpy(&query[query_len], QUERY_STARTER);
            query_len += strlen(QUERY_STARTER);
            strcpy(&query[query_len], QUERY_NAME);
            query_len += QUERY_NAME_LEN;
            strcpy(&query[query_len], context->endpointName);
            coap_set_header_uri_query(transaction->message, query);
        }
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

            if (query) {
                lwm2m_free(query);
            }

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

    int result = transaction_send(context, transaction);
    if (result != 0) {
        if (query) {
            lwm2m_free(query);
        }
    }

    return result;
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

static void _observe_callback(lwm2m_transaction_t *transaction, void *message)
{
    lwm2m_peer_t *client = NULL;
    lwm2m_peer_observation_t *obs = NULL;
    coap_packet_t *packet = (coap_packet_t *)message;
    c2c_observation_data_t *obs_data = (c2c_observation_data_t *)transaction->userData;
    lwm2m_uri_t *uri = &obs_data->uri;
    uint8_t code;

    client = (lwm2m_peer_t *)LWM2M_LIST_FIND(obs_data->context->clientList, obs_data->sec_inst_id);
    if (!client) {
        LOG("No client found");
        obs_data->callback(obs_data->id, uri, COAP_503_SERVICE_UNAVAILABLE, 0, NULL, 0,
                           obs_data->user_data);
        goto free_out;
    }

    obs = _find_peer_observation(client, uri);
    if (obs && obs->status == STATE_DEREG_PENDING) {
        code = COAP_400_BAD_REQUEST;
    }
    else if (!packet) {
        code = COAP_503_SERVICE_UNAVAILABLE;
    }
    else if (packet->code == COAP_205_CONTENT && !IS_OPTION(packet, COAP_OPTION_OBSERVE)) {
        code = COAP_405_METHOD_NOT_ALLOWED;
    }
    else {
        code = packet->code;
    }

    if (code != COAP_205_CONTENT) {
        /* if there is no payload, just call the callback */
        obs_data->callback(client->secObjInstID, uri, code, LWM2M_CONTENT_TEXT, NULL, 0,
                           obs_data->user_data);
    }
    else {
        if (!obs) {
            /* this was the first observation */
            obs = (lwm2m_peer_observation_t *)lwm2m_malloc(sizeof(lwm2m_peer_observation_t));
            if (!obs) {
                LOG("Could not allocate new observation");
                goto free_out;
            }
            memset(obs, 0, sizeof(lwm2m_peer_observation_t));
        }
        else {
            obs->client->observationList = (lwm2m_peer_observation_t *)
                                            LWM2M_LIST_RM(obs->client->observationList, obs->id,
                                                          NULL);
            /* TODO: give the user the change to free user data?? */
        }

        obs->id = obs_data->id;
        obs->client = client;
        obs->callback = obs_data->callback;
        obs->user_data = obs_data->user_data;
        obs->status = STATE_REGISTERED;
        memcpy(&obs->uri, uri, sizeof(lwm2m_uri_t));

        obs->client->observationList = (lwm2m_peer_observation_t *)
                                       LWM2M_LIST_ADD(obs->client->observationList, obs);
        obs_data->callback(obs_data->sec_inst_id, &obs_data->uri, 0,
                           utils_convertMediaType(packet->content_type), packet->payload,
                           packet->payload_len, obs_data->user_data);
    }

free_out:
    lwm2m_free(obs_data);
}

// #endif
