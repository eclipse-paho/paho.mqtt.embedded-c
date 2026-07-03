/*******************************************************************************
 * Copyright (c) 2023, 2026 Microsoft Corporation, Ian Craggs. All rights reserved.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 *******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "MQTTPacket.h"
#include "transport.h"
#include "v5log.h"

/* This is in order to get an asynchronous signal to stop the sample,
as the code loops waiting for msgs on the subscribed topic.
Your actual code will depend on your hw and approach*/
#include <signal.h>

int toStop = 0;

void cfinish(int sig)
{
	signal(SIGINT, NULL);
	toStop = 1;
}

void stop_init(void)
{
	signal(SIGINT, cfinish);
	signal(SIGTERM, cfinish);
}
/* */

int main(int argc, char *argv[])
{
	MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
	int rc = 0;
	int mysock = 0;
	unsigned char buf[200];
	int buflen = sizeof(buf);
	int msgid = 1;
	MQTTString topicString = MQTTString_initializer;
	unsigned char req_qos = 0;
	char* payload = "mypayload";
	int payloadlen = strlen(payload);
	int len = 0;
	char *host = "test.mosquitto.org";
	int port = 1884;
	MQTTTransport mytransport;
	MQTTProperty recv_properties_array[5];
	MQTTProperties recv_properties = MQTTProperties_initializer;
	recv_properties.array = recv_properties_array;
	recv_properties.max_count = 5;
	MQTTProperty send_properties_array[2];
	MQTTProperties send_properties = MQTTProperties_initializer;
	send_properties.array = send_properties_array;
	send_properties.max_count = 2;
	int server_topic_alias_max = 0;

	stop_init();
	if (argc > 1)
		host = argv[1];

	if (argc > 2)
		port = atoi(argv[2]);

	mysock = transport_open(host, port);
	if(mysock < 0)
		return mysock;

	printf("Sending to hostname %s port %d\n", host, port);

	mytransport.sck = &mysock;
	mytransport.getfn = transport_getdatanb;
	mytransport.state = 0;
	data.clientID.cstring = "paho-emb-v5pub0sub1_nb";
	data.keepAliveInterval = 20;
	data.cleansession = 1;
	data.username.cstring = "rw";
	data.password.cstring = "readwrite";
	data.MQTTVersion = 5;

	MQTTProperties conn_properties = MQTTProperties_initializer;
	MQTTProperties will_properties = MQTTProperties_initializer;

	len = MQTTV5Serialize_connect(buf, buflen, &data, &conn_properties, &will_properties);
	rc = transport_sendPacketBuffer(mysock, buf, len);

	/* wait for connack */
	if (MQTTPacket_read(buf, buflen, transport_getdata) == CONNACK)
	{
		unsigned char sessionPresent, connack_rc;

		if (MQTTV5Deserialize_connack(&recv_properties, &sessionPresent, &connack_rc, buf, buflen) != 1 
			|| connack_rc != 0)
		{
			printf("Unable to connect, return code %d (%s)\n", connack_rc, v5reasoncode_to_string(connack_rc));
			goto exit;
		}
	}
	else
		goto exit;

	printf("MQTTv5 connected: (%d properties)\n", recv_properties.count);
	for(int i = 0; i < recv_properties.count; i++)
	{
		if (recv_properties.array[i].identifier == MQTTPROPERTY_CODE_TOPIC_ALIAS_MAXIMUM)
		{
			server_topic_alias_max = recv_properties.array[i].value.integer2;
		}

		v5property_print(recv_properties.array[i]);
	}

	/* subscribe */
	MQTTProperties sub_properties = MQTTProperties_initializer;
	MQTTSubscribe_options sub_options = { 0 };
	topicString.cstring = "substopic";
	len = MQTTV5Serialize_subscribe(buf, buflen, 0, msgid, &sub_properties, 1, &topicString, &req_qos, &sub_options);

	rc = transport_sendPacketBuffer(mysock, buf, len);
	do {
		int frc;
		if ((frc=MQTTPacket_readnb(buf, buflen, &mytransport)) == SUBACK) /* wait for suback */
		{
			unsigned short submsgid;
			int subcount;
			unsigned char reason_code;

			rc = MQTTV5Deserialize_suback(&submsgid, &recv_properties, 1, &subcount, &reason_code, buf, buflen);
			if (reason_code != 0)
			{
				printf("granted qos != 0, %d (%s)\n", 
					reason_code, reason_code <= 2 ? "Granted QoS" : v5reasoncode_to_string(reason_code));
				goto exit;
			}

			printf("suback: (%d properties)\n", recv_properties.count);
			for(int i = 0; i < recv_properties.count; i++)
			{
				v5property_print(recv_properties.array[i]);
			}

			break;
		}
		else if (frc == -1)
			goto exit;
	} while (1); /* handle timeouts here */

	/* publish first message and configure topic alias */
	printf("publishing reading\n");
		
	MQTTProperty property_topic_alias = {
		.identifier = MQTTPROPERTY_CODE_TOPIC_ALIAS,
		.value.integer2 = 1
	};

	if (server_topic_alias_max >= 1)
	{
		rc = MQTTProperties_add(&send_properties, &property_topic_alias);
		if (rc)
		{
			printf("Failed to add topic alias\n");
			goto exit;
		}
	}
	
	char* property_key = "user key";
	char* property_value = "user value";
	MQTTProperty user_property = {
		.identifier = MQTTPROPERTY_CODE_USER_PROPERTY,
		.value.string_pair.key.data = property_key,
		.value.string_pair.key.len = strlen(property_key),
		.value.string_pair.val.data = property_value,
		.value.string_pair.val.len = strlen(property_value),
	};

	rc = MQTTProperties_add(&send_properties, &user_property);
	if (rc)
	{
		printf("Failed to add user property\n");
		goto exit;
	}

	topicString.cstring = "pubtopic";

	len = MQTTV5Serialize_publish(buf, buflen, 0, 0, 0, 0, topicString, &send_properties, 
				(unsigned char *)payload, payloadlen);
	rc = transport_sendPacketBuffer(mysock, buf, len);

	/* loop getting msgs on subscribed topic */
	while (!toStop)
	{
		/* handle timeouts */
		rc = MQTTPacket_readnb(buf, buflen, &mytransport); 
		unsigned char dup;
		unsigned short msgid;

		switch (rc)
		{
			case 0:
				// call-again (no-op).
				break;

			case -1:
				printf("read error\n");
				toStop = 1;
				break;

			case PUBLISH:
			{
				unsigned char qos;
				unsigned char retained;
				int payloadlen_in;
				unsigned char* payload_in;
				MQTTString receivedTopic;

				rc = MQTTV5Deserialize_publish(&dup, &qos, &retained, &msgid, &receivedTopic, &recv_properties, 
						&payload_in, &payloadlen_in, buf, buflen);
				printf("message arrived %.*s\n", payloadlen_in, payload_in);

				printf("message has %d properties\n", recv_properties.count);
				for(int i = 0; i < recv_properties.count; i++)
				{
					v5property_print(recv_properties.array[i]);
				}

				if (server_topic_alias_max >= 1)
				{
					printf("publishing using topic alias / reading\n");
					topicString.cstring = "";
				}
				else 
				{
					printf("publishing reading\n");
				}

				len = MQTTV5Serialize_publish(buf, buflen, 0, 0, 0, 0, topicString, &send_properties, 
							(unsigned char *)payload, payloadlen);
				rc = transport_sendPacketBuffer(mysock, buf, len);
			}
			break;

			case DISCONNECT:
			{
				unsigned char reason_code;
				toStop = 1;
				printf("disconnect received\n");
				rc = MQTTV5Deserialize_disconnect(&recv_properties, &reason_code, buf, buflen);
				printf("\tdisconnect details: reason=%d (%s)\n", reason_code, v5reasoncode_to_string(reason_code));

				printf("disconnect has %d properties\n", recv_properties.count);
				for(int i = 0; i < recv_properties.count; i++)
				{
					v5property_print(recv_properties.array[i]);
				}
			}
			break;

			default:
				printf("unknown message type (%d)\n", rc);
		}
	}

	printf("disconnecting\n");
	len = MQTTSerialize_disconnect(buf, buflen);
	rc = transport_sendPacketBuffer(mysock, buf, len);

exit:
	transport_close(mysock);

	return 0;
}
