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

#include "V5/MQTTV5Packet.h"
#include "transport.h"
#include "v5log.h"

#define KEEPALIVE_INTERVAL 20

/* This is to get a timebase in seconds to test the sample */
#include <time.h>
time_t old_t;
void start_ping_timer(void)
{
	time(&old_t);
	old_t += KEEPALIVE_INTERVAL/2 + 1;
}

int time_to_ping(void)
{
time_t t;

	time(&t);
	if(t >= old_t)
	  	return 1;
	return 0;
}

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
	int len = 0;
	char *host = "test.mosquitto.org";
	int port = 1884;
	MQTTProperty connack_properties_array[5];
	MQTTProperties connack_properties = MQTTProperties_initializer;

	connack_properties.array = connack_properties_array;
	connack_properties.max_count = 5;

	stop_init();
	if (argc > 1)
		host = argv[1];

	if (argc > 2)
		port = atoi(argv[2]);

	mysock = transport_open(host, port);
	if(mysock < 0)
		return mysock;

	printf("Sending to hostname %s port %d\n", host, port);

	data.clientID.cstring = "paho-emb-ping";
	data.keepAliveInterval = KEEPALIVE_INTERVAL;
	data.cleansession = 1;
	data.username.cstring = "rw";
	data.password.cstring = "readwrite";
	data.MQTTVersion = 5;

	MQTTProperties conn_properties = MQTTProperties_initializer;
	MQTTProperties will_properties = MQTTProperties_initializer;

	len = MQTTV5Serialize_connect(buf, buflen, &data, &conn_properties, &will_properties);
	rc = transport_sendPacketBuffer(mysock, buf, len);

	printf("Sent MQTTv5 connect\n");
	/* wait for connack */
	if (MQTTPacket_read(buf, buflen, transport_getdata) == CONNACK)
	{
		unsigned char sessionPresent, connack_rc;

		if (MQTTV5Deserialize_connack(&connack_properties, &sessionPresent, &connack_rc, buf, buflen) != 1 
			|| connack_rc != 0)
		{
			printf("Unable to connect, return code %d\n", connack_rc);
			goto exit;
		}
	}
	else
		goto exit;

	printf("MQTTv5 connected: (%d properties)\n", connack_properties.count);
	for(int i = 0; i < connack_properties.count; i++)
	{
		v5property_print(connack_properties.array[i]);
	}

	start_ping_timer();

	while (!toStop)
	{
		while(!time_to_ping());
		len = MQTTSerialize_pingreq(buf, buflen);
		transport_sendPacketBuffer(mysock, buf, len);
		printf("Ping...");
		if (MQTTPacket_read(buf, buflen, transport_getdata) == PINGRESP){
			printf("Pong\n");
			start_ping_timer();
		}
		else {
			printf("OOPS\n");
			goto exit;
		}
		
	}

	printf("disconnecting\n");

	MQTTProperties disconn_properties = MQTTProperties_initializer;
	len = MQTTV5Serialize_disconnect(buf, buflen, MQTTREASONCODE_NORMAL_DISCONNECTION, &disconn_properties);

	rc = transport_sendPacketBuffer(mysock, buf, len);

exit:
	transport_close(mysock);

	return 0;
}
