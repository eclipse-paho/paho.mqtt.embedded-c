/*******************************************************************************
 * Copyright (c) 2014, 2017 IBM Corp.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *   Allan Stockdill-Mander/Ian Craggs - initial API and implementation and/or initial documentation
 *   Ian Craggs - fix for #96 - check rem_len in readPacket
 *   Ian Craggs - add ability to set message handler separately #6
 *******************************************************************************/
#include "MQTTClient.h"

#include <stdio.h>
#include <string.h>

static void NewMessageData(MessageData* md, MQTTString* aTopicName, MQTTMessage* aMessage) {
    md->topicName = aTopicName;
    md->message = aMessage;
}


static int getNextPacketId(MQTTClient *c) {
    return c->next_packetid = (c->next_packetid == MAX_PACKET_ID) ? 1 : c->next_packetid + 1;
}


static int sendPacket(MQTTClient* c, int length, Timer* timer)
{
    int rc = FAILURE,
        sent = 0;

    while (sent < length && !TimerIsExpired(timer))
    {
        rc = c->ipstack->mqttwrite(c->ipstack, &c->buf[sent], length - sent, TimerLeftMS(timer));
        if (rc < 0)  // there was an error writing the data
            break;
        sent += rc;
    }
    if (sent == length)
    {
        TimerCountdown(&c->last_sent, c->keepAliveInterval); // record the fact that we have successfully sent the packet
        rc = SUCCESS;
    }
    else
        rc = FAILURE;
    return rc;
}


void MQTTClientInit(MQTTClient* c, Network* network, unsigned int command_timeout_ms, \
                    void* (*mem_calloc)(unsigned int n, unsigned int size), void (*mem_free)(void *addr_ptr))
{
    c->ipstack = network;

    c->command_timeout_ms = command_timeout_ms;
    c->buf = NULL;
    c->buf_size = 0;
    c->readbuf = NULL;
    c->readbuf_size = 0;
    c->isconnected = 0;
    c->cleansession = 0;
    c->ping_outstanding = 0;
    c->defaultMessageHandler = NULL;
    c->next_packetid = 1;

    c->try_cnt = 6;

    c->max_message_handlers = 0;
    c->messageHandlers = NULL;

    c->mem_calloc = mem_calloc;
    c->mem_free = mem_free;
    
    TimerInit(&c->last_sent);
    TimerInit(&c->last_received);
#if defined(MQTT_TASK)
	  MutexInit(&c->mutex);
#endif
}


static int decodePacket(MQTTClient* c, int* value, int timeout)
{
    unsigned char i;
    int multiplier = 1;
    int len = 0;
    const int MAX_NO_OF_REMAINING_LENGTH_BYTES = 4;

    *value = 0;
    do
    {
        int rc = MQTTPACKET_READ_ERROR;

        if (++len > MAX_NO_OF_REMAINING_LENGTH_BYTES)
        {
            rc = MQTTPACKET_READ_ERROR; /* bad data */
            goto exit;
        }
        rc = c->ipstack->mqttread(c->ipstack, &i, 1, timeout);
        if (rc != 1)
            goto exit;
        *value += (i & 127) * multiplier;
        multiplier *= 128;
    } while ((i & 128) != 0);
exit:
    return len;
}


static unsigned char * CallocNewBuff(MQTTClient* c, int is_read, int must_new, int new_size)
{
    if(is_read != 0)
    {
        /* Return old buffer when not must new mode and buffer size over. */
        if(must_new == 0)
        {
            if((c->readbuf != NULL) && (new_size <= c->readbuf_size))
            {
                return c->readbuf;
            }
        }
        
        /* Reset previous read buffer and create new one. */
        if(c->readbuf != NULL)
        {
            c->mem_free(c->readbuf);
            c->readbuf = NULL;
            c->readbuf_size = 0;
        }
        
        c->readbuf_size = new_size;
        if((c->readbuf = (unsigned char*)c->mem_calloc(1, c->readbuf_size)) == NULL)
        {
            c->readbuf_size = 0;
        }

        return c->readbuf;
    }
    else
    {
        /* Return old buffer when not must new mode and buffer size over. */
        if(must_new == 0)
        {
            if((c->buf != NULL) && (new_size <= c->buf_size))
            {
                return c->buf;
            }
        }
        
        /* Reset previous read buffer and create new one. */
        if(c->buf != NULL)
        {
            c->mem_free(c->buf);
            c->buf = NULL;
            c->buf_size = 0;
        }
        
        c->buf_size = new_size;
        if((c->buf = (unsigned char*)c->mem_calloc(1, c->buf_size)) == NULL)
        {
            c->buf_size = 0;
        }

        return c->buf;
    }
}


void FreeAllBuff(MQTTClient* c)
{
    /* Free all the memory. */
    if(c->readbuf != NULL)
    {
        c->mem_free(c->readbuf);
        c->readbuf = NULL;
        c->readbuf_size = 0;
    }
    if(c->buf != NULL)
    {
        c->mem_free(c->buf);
        c->buf = NULL;
        c->buf_size = 0;
    }
}

static int readPacket(MQTTClient* c, Timer* timer)
{
    MQTTHeader header = {0};
    int len = 0;
    int rem_len = 0;
    unsigned char first_byte = 0;

    /* 1. read the header byte(packet type). Only wait 5ms, jump out when no data and free cpu. */
    int rc = c->ipstack->mqttread(c->ipstack, &first_byte, 1, 5);
    if (rc != 1)
        goto exit;

    len = 1;
    /* 2. read the remaining length.  This is variable in itself */
    decodePacket(c, &rem_len, TimerLeftMS(timer));

    /* Reset previous read buffer and create new one. */
    if(CallocNewBuff(c, 1, 1, rem_len + 10) == NULL)
    {
        rc = BUFFER_OVERFLOW;
        goto exit;
    }
    
    c->readbuf[0]= first_byte;
    len += MQTTPacket_encode(c->readbuf + 1, rem_len); /* put the original remaining length back into the buffer */

    if (rem_len > (c->readbuf_size - len))
    {
        rc = BUFFER_OVERFLOW;
        goto exit;
    }

    /* 3. read the rest of the buffer using a callback to supply the rest of the data */
    if (rem_len > 0) 
    {
        rc = c->ipstack->mqttread(c->ipstack, c->readbuf + len, rem_len, TimerLeftMS(timer));
        if(rc != rem_len)
        {
            rc = 0;
            goto exit;
        }
    }

    header.byte = c->readbuf[0];
    rc = header.bits.type;
    if (c->keepAliveInterval > 0)
        TimerCountdown(&c->last_received, c->keepAliveInterval); // record the fact that we have successfully received a packet
exit:
    return rc;
}


// assume topic filter and name is in correct format
// # can only be at end
// + and # can only be next to separator
static char isTopicMatched(char* topicFilter, MQTTString* topicName)
{
    char* curf = topicFilter;
    char* curn = topicName->lenstring.data;
    char* curn_end = curn + topicName->lenstring.len;

    while (*curf && curn < curn_end)
    {
        if (*curn == '/' && *curf != '/')
            break;
        if (*curf != '+' && *curf != '#' && *curf != *curn)
            break;
        if (*curf == '+')
        {   // skip until we meet the next separator, or end of string
            char* nextpos = curn + 1;
            while (nextpos < curn_end && *nextpos != '/')
                nextpos = ++curn + 1;
        }
        else if (*curf == '#')
            curn = curn_end - 1;    // skip until end of string
        curf++;
        curn++;
    };

    return (curn == curn_end) && (*curf == '\0');
}


int deliverMessage(MQTTClient* c, MQTTString* topicName, MQTTMessage* message)
{
    int i;
    int rc = FAILURE;

    // we have to find the right message handler - indexed by topic
    for (i = 0; i < c->max_message_handlers; ++i)
    {
        if (c->messageHandlers[i].topicFilter != 0 && (MQTTPacket_equals(topicName, (char*)c->messageHandlers[i].topicFilter) ||
                isTopicMatched((char*)c->messageHandlers[i].topicFilter, topicName)))
        {
            if (c->messageHandlers[i].fp != NULL)
            {
                MessageData md;
                NewMessageData(&md, topicName, message);
                c->messageHandlers[i].fp(c->messageHandlers[i].context_ptr, &md);
                rc = SUCCESS;
            }
        }
    }

    if (rc == FAILURE && c->defaultMessageHandler != NULL)
    {
        MessageData md;
        NewMessageData(&md, topicName, message);
        c->defaultMessageHandler(c->defaultMessageCtx_ptr, &md);
        rc = SUCCESS;
    }

    return rc;
}


int keepalive(MQTTClient* c)
{
    int rc = SUCCESS;
    static int cnt = 0;
    int len = 0;

    if (c->keepAliveInterval == 0)
        goto exit;

    if (TimerIsExpired(&c->last_sent) || TimerIsExpired(&c->last_received))
    {
        if((c->ping_outstanding) && (cnt > c->try_cnt))
        {
            cnt = 0;
            rc = FAILURE; /* PINGRESP not received in keepalive interval */
        }
        else
        {
            Timer timer;

            /* Every time when start ping process reset the cnt value. */
            if(c->ping_outstanding == 0)
            {
                cnt = 0;
            }
            
            TimerInit(&timer);
            TimerCountdownMS(&timer, 1000);

            /* Reset previous read buffer and create new one. */
            if(CallocNewBuff(c, 0, 0, 10) != NULL)
            {
                len = MQTTSerialize_pingreq(c->buf, c->buf_size);
                if (len > 0 && (rc = sendPacket(c, len, &timer)) == SUCCESS) // send the ping packet
                {
                    c->ping_outstanding = 1;
                }
            }
            
            cnt ++;
        }
    }

exit:
    return rc;
}


void MQTTCleanSession(MQTTClient* c)
{
    int i = 0;

    for (i = 0; i < c->max_message_handlers; ++i)
        c->messageHandlers[i].topicFilter = NULL;
}


void MQTTCloseSession(MQTTClient* c)
{
    c->ping_outstanding = 0;
    c->isconnected = 0;
    if (c->cleansession)
        MQTTCleanSession(c);
}


int cycle(MQTTClient* c, Timer* timer)
{
    int len = 0,
        rc = SUCCESS;
    unsigned int waittime = TimerLeftMS(timer);

    int packet_type = readPacket(c, timer);     /* read the socket, see what work is due */

    switch (packet_type)
    {
        default:
            /* no more data to read, unrecoverable. Or read packet fails due to unexpected network error */
            rc = packet_type;
            goto exit;
        case 0: /* timed out reading packet */
            break;
        case CONNACK:
        case PUBACK:
        case SUBACK:
        case UNSUBACK:
            break;
        case PUBLISH:
        {
            MQTTString topicName;
            MQTTMessage msg;
            int intQoS;
            msg.payloadlen = 0; /* this is a size_t, but deserialize publish sets this as int */
            if (MQTTDeserialize_publish(&msg.dup, &intQoS, &msg.retained, &msg.id, &topicName,
               (unsigned char**)&msg.payload, (int*)&msg.payloadlen, c->readbuf, c->readbuf_size) != 1)
                goto exit;
            msg.qos = (enum QoS)intQoS;
            deliverMessage(c, &topicName, &msg);
            if (msg.qos != QOS0)
            {
                /* Reset previous read buffer and create new one. */
                if(CallocNewBuff(c, 0, 0, 10) == NULL)
                {
                    rc = FAILURE;
                    goto exit;
                }
                
                if (msg.qos == QOS1)
                    len = MQTTSerialize_ack(c->buf, c->buf_size, PUBACK, 0, msg.id);
                else if (msg.qos == QOS2)
                    len = MQTTSerialize_ack(c->buf, c->buf_size, PUBREC, 0, msg.id);
                if (len <= 0)
                    rc = FAILURE;
                else
                {
                    /* Reset the waittime before sending packet. because routine 'deliverMessage' would use a lot. */
                    TimerCountdownMS(timer, waittime);
                    rc = sendPacket(c, len, timer);
                }
                if (rc == FAILURE)
                    goto exit; // there was a problem
            }
            break;
        }
        case PUBREC:
        case PUBREL:
        {
            unsigned short mypacketid;
            unsigned char dup, type;

            /* Reset the waittime before sendint packet. only in case. */
            TimerCountdownMS(timer, waittime);

            /* Reset previous read buffer and create new one. */
            if(CallocNewBuff(c, 0, 0, 10) == NULL)
            {
                rc = FAILURE;
                goto exit;
            }
            
            if (MQTTDeserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) != 1)
                rc = FAILURE;
            else if ((len = MQTTSerialize_ack(c->buf, c->buf_size,
                (packet_type == PUBREC) ? PUBREL : PUBCOMP, 0, mypacketid)) <= 0)
                rc = FAILURE;
            else if ((rc = sendPacket(c, len, timer)) != SUCCESS) // send the PUBREL packet
                rc = FAILURE; // there was a problem
            if (rc == FAILURE)
                goto exit; // there was a problem
            break;
        }

        case PUBCOMP:
            break;
        case PINGRESP:
            c->ping_outstanding = 0;
            break;
    }

    if (keepalive(c) != SUCCESS) {
        //check only keepalive FAILURE status so that previous FAILURE status can be considered as FAULT
        rc = FAILURE;
    }

exit:
    if (rc == SUCCESS)
        rc = packet_type;
    else if (c->isconnected)
        MQTTCloseSession(c);
    return rc;
}


int MQTTYield(MQTTClient* c, int timeout_ms)
{
    int rc = SUCCESS;
    Timer timer;

    TimerInit(&timer);
    TimerCountdownMS(&timer, timeout_ms);

    /* Call the read process only once, the timeout_ms valid only when have getted first byte in 5ms. 
    caution: Do not watting for timeout_ms, because this routine only be called periodically in back task,
    and this can give other code cpu time for this bask task. */
    do
    {
        rc = cycle(c, &timer);

    } while (0);

    return rc;
}

int MQTTIsConnected(MQTTClient* client)
{
  return client->isconnected;
}

void MQTTRun(void* parm)
{
	Timer timer;
	MQTTClient* c = (MQTTClient*)parm;

    
	TimerInit(&timer);

	while (1)
	{
		/* Wait 100ms for other thread and start the next detect operation. */
        //ThreadSleep(100);

#if defined(MQTT_TASK)
		MutexLock(&c->mutex);
#endif
		TimerCountdownMS(&timer, 500); /* Don't wait too long if no traffic is incoming */
		cycle(c, &timer);
#if defined(MQTT_TASK)
		MutexUnlock(&c->mutex);
#endif
	}
}


#if defined(MQTT_TASK)
int MQTTStartTask(MQTTClient* client)
{
	return ThreadStart(&client->thread, &MQTTRun, client);
}
#endif


int waitfor(MQTTClient* c, int packet_type, Timer* timer)
{
    int rc = FAILURE;

    do
    {
        /* Read once no matter whatever for timer. */
        rc = cycle(c, timer);
        if(TimerIsExpired(timer))
        {
            if(rc <= 0)
            {
                /* Stop loop when no data received or read error. */
                break;
            }
            else
            {
                /* Give more 500ms for next reading when reading other valid type packet. */
                TimerCountdownMS(timer, 500);
            }
        }
    }
    while (rc != packet_type && rc >= 0);

    return rc;
}


int MQTTConnectWithResults(MQTTClient* c, MQTTPacket_connectData* options, MQTTConnackData* data)
{
    Timer connect_timer;
    int rc = FAILURE;
    MQTTPacket_connectData default_options = MQTTPacket_connectData_initializer;
    int len = 0;
    int cnt = 0;

#if defined(MQTT_TASK)
	  MutexLock(&c->mutex);
#endif
	  if (c->isconnected) /* don't send connect packet again if we are already connected */
		  goto exit;

SEND_START:
    TimerInit(&connect_timer);
    TimerCountdownMS(&connect_timer, c->command_timeout_ms);

    if (options == 0)
        options = &default_options; /* set default options if none were supplied */

    c->keepAliveInterval = options->keepAliveInterval;
    c->cleansession = options->cleansession;
    TimerCountdown(&c->last_received, c->keepAliveInterval);

    /* Reset previous read buffer and create new one. */
    if(CallocNewBuff(c, 0, 0, MQTTPacket_len(MQTTSerialize_connectLength(options)) + 10) == NULL)
    {
        rc = BUFFER_OVERFLOW;
        goto exit;
    }
    
    if ((len = MQTTSerialize_connect(c->buf, c->buf_size, options)) <= 0)
        goto exit;
    if ((rc = sendPacket(c, len, &connect_timer)) != SUCCESS)  // send the connect packet
        goto exit; // there was a problem

    // this will be a blocking call, wait for the connack
    if (waitfor(c, CONNACK, &connect_timer) == CONNACK)
    {
        data->rc = 0;
        data->sessionPresent = 0;
        if (MQTTDeserialize_connack(&data->sessionPresent, &data->rc, c->readbuf, c->readbuf_size) == 1)
            rc = data->rc;
        else
            rc = FAILURE;
    }
    else
    {
        cnt ++;
        if(cnt <= c->try_cnt)
        {
            goto SEND_START;
        }
        else
        {
            rc = FAILURE;
        }
    }

exit:
    if (rc == SUCCESS)
    {
        c->isconnected = 1;
        c->ping_outstanding = 0;
    }

#if defined(MQTT_TASK)
	  MutexUnlock(&c->mutex);
#endif

    return rc;
}


int MQTTConnect(MQTTClient* c, MQTTPacket_connectData* options)
{
    MQTTConnackData data;
    return MQTTConnectWithResults(c, options, &data);
}


int MQTTSetMessageHandler(MQTTClient* c, const char* topicFilter, messageHandler msgHandler, void *context_ptr)
{
    int rc = FAILURE;
    int i = -1;
    MessageHandlers * new_msghdler_ptr = NULL;
    int                   new_maxhdler = 0;


SETMSG_START:
    
    /* first check for an existing matching slot */
    for (i = 0; i < c->max_message_handlers; ++i)
    {
        if (c->messageHandlers[i].topicFilter != NULL && strcmp(c->messageHandlers[i].topicFilter, topicFilter) == 0)
        {
            if (msgHandler == NULL) /* remove existing */
            {
                c->messageHandlers[i].topicFilter = NULL;
                c->messageHandlers[i].fp = NULL;
            }
            rc = SUCCESS; /* return i when adding new subscription */
            break;
        }
    }
    /* if no existing, look for empty slot (unless we are removing) */
    if (msgHandler != NULL) {
        if (rc == FAILURE)
        {
            for (i = 0; i < c->max_message_handlers; ++i)
            {
                if (c->messageHandlers[i].topicFilter == NULL)
                {
                    rc = SUCCESS;
                    break;
                }
            }
        }

        if (i < c->max_message_handlers)
        {
            c->messageHandlers[i].topicFilter = topicFilter;
            c->messageHandlers[i].fp = msgHandler;
            c->messageHandlers[i].context_ptr = context_ptr;
        }
        else
        {
            new_maxhdler = c->max_message_handlers + 30;
            if((new_msghdler_ptr = (MessageHandlers*)c->mem_calloc(new_maxhdler, sizeof(*new_msghdler_ptr))) != NULL)
            {
                if(c->messageHandlers != NULL)
                {
                    memcpy(new_msghdler_ptr, c->messageHandlers, c->max_message_handlers * sizeof(*c->messageHandlers));
                    c->mem_free(c->messageHandlers);
                }
                c->messageHandlers = new_msghdler_ptr;
                c->max_message_handlers = new_maxhdler;

                goto SETMSG_START;
            }
            else
            {
                rc = FAILURE;
            } 
        }
    }
    return rc;
}


int MQTTSubscribeWithResults(MQTTClient* c, const char* topicFilter, enum QoS qos,
       messageHandler msgHandler, void *context_ptr, MQTTSubackData* data)
{
    int rc = FAILURE;
    Timer timer;
    int len = 0;
    MQTTString topic = MQTTString_initializer;
    int cnt = 0;
    topic.cstring = (char *)topicFilter;
    

#if defined(MQTT_TASK)
	  MutexLock(&c->mutex);
#endif
	  if (!c->isconnected)
		    goto exit;

SEND_START:    
    TimerInit(&timer);
    TimerCountdownMS(&timer, c->command_timeout_ms);

    /* Reset previous read buffer and create new one. */
    if(CallocNewBuff(c, 0, 0, MQTTPacket_len(MQTTSerialize_subscribeLength(1, &topic)) + 10) == NULL)
    {
        rc = BUFFER_OVERFLOW;
        goto exit;
    }

    len = MQTTSerialize_subscribe(c->buf, c->buf_size, 0, getNextPacketId(c), 1, &topic, (int*)&qos);
    if (len <= 0)
        goto exit;


    if ((rc = sendPacket(c, len, &timer)) != SUCCESS) // send the subscribe packet
        goto exit;             // there was a problem

    if (waitfor(c, SUBACK, &timer) == SUBACK)      // wait for suback
    {
        int count = 0;
        unsigned short mypacketid;
        data->grantedQoS = QOS0;
        if (MQTTDeserialize_suback(&mypacketid, 1, &count, (int*)&data->grantedQoS, c->readbuf, c->readbuf_size) == 1)
        {
            if (data->grantedQoS != 0x80)
            {
                rc = MQTTSetMessageHandler(c, topicFilter, msgHandler, context_ptr);
            }
            else
            {
                rc = FAILURE;
            }
        }
    }
    else
    {
        cnt ++;
        if(cnt <= c->try_cnt)
        {
            goto SEND_START;
        }
        else
        {
            rc = FAILURE;
        }
    }

exit:
    if (rc == FAILURE)
        MQTTCloseSession(c);
#if defined(MQTT_TASK)
	  MutexUnlock(&c->mutex);
#endif
    return rc;
}


int MQTTSubscribe(MQTTClient* c, const char* topicFilter, enum QoS qos,
       messageHandler msgHandler, void *context_ptr)
{
    MQTTSubackData data;
    return MQTTSubscribeWithResults(c, topicFilter, qos, msgHandler, context_ptr, &data);
}


int MQTTUnsubscribe(MQTTClient* c, const char* topicFilter)
{
    int rc = FAILURE;
    Timer timer;
    MQTTString topic = MQTTString_initializer;

    int len = 0;
    int cnt = 0;
    topic.cstring = (char *)topicFilter;


#if defined(MQTT_TASK)
	  MutexLock(&c->mutex);
#endif
	  if (!c->isconnected)
		  goto exit;

SEND_START:
    TimerInit(&timer);
    TimerCountdownMS(&timer, c->command_timeout_ms);

    /* Reset previous read buffer and create new one. */
    if(CallocNewBuff(c, 0, 0, MQTTPacket_len(MQTTSerialize_unsubscribeLength(1, &topic)) + 10) == NULL)
    {
        rc = BUFFER_OVERFLOW;
        goto exit;
    }

    if ((len = MQTTSerialize_unsubscribe(c->buf, c->buf_size, 0, getNextPacketId(c), 1, &topic)) <= 0)
        goto exit;
    if ((rc = sendPacket(c, len, &timer)) != SUCCESS) // send the subscribe packet
        goto exit; // there was a problem

    if (waitfor(c, UNSUBACK, &timer) == UNSUBACK)
    {
        unsigned short mypacketid;  // should be the same as the packetid above
        if (MQTTDeserialize_unsuback(&mypacketid, c->readbuf, c->readbuf_size) == 1)
        {
            /* remove the subscription message handler associated with this topic, if there is one */
            MQTTSetMessageHandler(c, topicFilter, NULL, NULL);
        }
    }
    else
    {
        cnt ++;
        if(cnt <= c->try_cnt)
        {
            goto SEND_START;
        }
        else
        {
            rc = FAILURE;
        }
    }

exit:
    if (rc == FAILURE)
        MQTTCloseSession(c);
#if defined(MQTT_TASK)
	  MutexUnlock(&c->mutex);
#endif
    return rc;
}


int MQTTPublish(MQTTClient* c, const char* topicName, MQTTMessage* message)
{
    int rc = FAILURE;
    Timer timer;
    MQTTString topic = MQTTString_initializer;

    int len = 0;
    int cnt = 0;
    topic.cstring = (char *)topicName;


#if defined(MQTT_TASK)
	  MutexLock(&c->mutex);
#endif
	  if (!c->isconnected)
		    goto exit;

SEND_START:
    TimerInit(&timer);
    TimerCountdownMS(&timer, c->command_timeout_ms);

    if (message->qos == QOS1 || message->qos == QOS2)
        message->id = getNextPacketId(c);

    /* Reset previous read buffer and create new one. */
    if(CallocNewBuff(c, 0, 1, MQTTPacket_len(MQTTSerialize_publishLength(message->qos, topic, message->payloadlen)) + 10) == NULL)
    {
        rc = BUFFER_OVERFLOW;
        goto exit;
    }

    len = MQTTSerialize_publish(c->buf, c->buf_size, 0, message->qos, message->retained, message->id,
              topic, (unsigned char*)message->payload, message->payloadlen);
    if (len <= 0)
        goto exit;
    if ((rc = sendPacket(c, len, &timer)) != SUCCESS) // send the subscribe packet
        goto exit; // there was a problem

    if (message->qos == QOS1)
    {
        if (waitfor(c, PUBACK, &timer) == PUBACK)
        {
            unsigned short mypacketid;
            unsigned char dup, type;
            if (MQTTDeserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) != 1)
                rc = FAILURE;
        }
        else
        {
            cnt ++;
            if(cnt <= c->try_cnt)
            {
                goto SEND_START;
            }
            else
            {
                rc = FAILURE;
            }
        }
    }
    else if (message->qos == QOS2)
    {
        if (waitfor(c, PUBCOMP, &timer) == PUBCOMP)
        {
            unsigned short mypacketid;
            unsigned char dup, type;
            if (MQTTDeserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) != 1)
                rc = FAILURE;
        }
        else
        {
            cnt ++;
            if(cnt <= c->try_cnt)
            {
                goto SEND_START;
            }
            else
            {
                rc = FAILURE;
            }
        }
    }

exit:
    if (rc == FAILURE)
        MQTTCloseSession(c);
#if defined(MQTT_TASK)
	  MutexUnlock(&c->mutex);
#endif
    return rc;
}


int MQTTDisconnect(MQTTClient* c)
{
    int rc = FAILURE;
    Timer timer;     // we might wait for incomplete incoming publishes to complete
    int len = 0;

#if defined(MQTT_TASK)
	MutexLock(&c->mutex);
#endif
    TimerInit(&timer);
    TimerCountdownMS(&timer, c->command_timeout_ms);


    /* Reset previous read buffer and create new one. */
    if(CallocNewBuff(c, 0, 0, 10) != NULL)
    {
        len = MQTTSerialize_disconnect(c->buf, c->buf_size);
        if (len > 0)
            rc = sendPacket(c, len, &timer);            // send the disconnect packet
    }

    MQTTCloseSession(c);
    FreeAllBuff(c);

    if(c->messageHandlers != NULL)
    {
        c->mem_free(c->messageHandlers);
        c->messageHandlers = NULL;
    }
    c->max_message_handlers = 0;

#if defined(MQTT_TASK)
	  MutexUnlock(&c->mutex);
#endif
    return rc;
}
