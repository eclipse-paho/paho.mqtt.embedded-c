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

int main(int argc, char *argv[])
{
	MQTTPacket_connectData conn_data = MQTTPacket_connectData_initializer;
	int rc = 0;
	char buf[200];
	int buflen = sizeof(buf);
	int mysock = 0;
	MQTTString topicString = MQTTString_initializer;
	char* payload = "mypayload";
	int payloadlen = strlen(payload);
	int len = 0;
	char *host = "test.mosquitto.org";
	int port = 1884;

	if (argc > 1)
		host = argv[1];

	if (argc > 2)
		port = atoi(argv[2]);

	mysock = transport_open(host,port);
	if(mysock < 0)
		return mysock;

	printf("Sending to hostname %s port %d\n", host, port);

	conn_data.clientID.cstring = "paho-emb-v5qos0pub";
	conn_data.keepAliveInterval = 20;
	conn_data.cleansession = 1;
	conn_data.username.cstring = "rw";
	conn_data.password.cstring = "readwrite";
	conn_data.MQTTVersion = 5;

	MQTTProperties conn_properties = MQTTProperties_initializer;
	MQTTProperties will_properties = MQTTProperties_initializer;
	
	len = MQTTV5Serialize_connect((unsigned char *)buf, buflen, &conn_data, &conn_properties, &will_properties);

	MQTTProperty pub_properties_array[1];
	MQTTProperties pub_properties = MQTTProperties_initializer;
	pub_properties.array = pub_properties_array;
	pub_properties.max_count = 1;

	MQTTProperty v5property;
	v5property.identifier = MQTTPROPERTY_CODE_USER_PROPERTY;
	v5property.value.string_pair.key.data = "user key";
	v5property.value.string_pair.key.len = strlen(v5property.value.string_pair.key.data);
	v5property.value.string_pair.val.data = "user value";
	v5property.value.string_pair.val.len = strlen(v5property.value.string_pair.val.data);
	rc = MQTTProperties_add(&pub_properties, &v5property);
	if (rc)
	{
		printf("Failed to add user property\n");
		goto exit;
	}

	topicString.cstring = "mytopicv5";
	len += MQTTV5Serialize_publish((unsigned char *)(buf + len), buflen - len, 0, 1, 0, 123, topicString, &pub_properties, (unsigned char *)payload, payloadlen);

	MQTTProperties disconnect_properties = MQTTProperties_initializer;
	len += MQTTV5Serialize_disconnect((unsigned char *)(buf + len), buflen - len, MQTTREASONCODE_NORMAL_DISCONNECTION, &disconnect_properties);

	rc = transport_sendPacketBuffer(mysock, (unsigned char*)buf, len);
	if (rc == len)
		printf("Successfully published v5\n");
	else
		printf("Publish failed\n");

exit:
	transport_close(mysock);

	return 0;
}
