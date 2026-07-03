/*******************************************************************************
 * Copyright (c) 2014, 2026 IBM Corp., Ian Craggs and others
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
 * Contributors:
 *    Ian Craggs - initial API and implementation and/or initial documentation
 *    Ian Craggs - MQTT V5 implementation
 *******************************************************************************/

#if defined(MQTTV5)
#include "V5/MQTTV5Packet.h"
#else
#include "MQTTPacket.h"
#endif

#include "StackTrace.h"

#include <string.h>

/**
  * Determines the length of the MQTT unsubscribe packet that would be produced using the supplied parameters
  * @param count the number of topic filter strings in topicFilters
  * @param topicFilters the array of topic filter strings to be used in the publish
  * @return the length of buffer needed to contain the serialized version of the packet
  */
#if defined(MQTTV5)
int32_t MQTTSerialize_unsubscribeLength(int count, MQTTString topicFilters[], MQTTProperties* properties)
#else
int32_t MQTTSerialize_unsubscribeLength(int count, MQTTString topicFilters[])
#endif
{
	int i;
	int32_t len = 2; /* packetid */

	for (i = 0; i < count; ++i)
		len += 2 + MQTTstrlen(topicFilters[i]); /* length + topic*/
#if defined(MQTTV5)
	if (properties)
		len += MQTTProperties_len(properties);
#endif
	return len;
}


/**
  * Serializes the supplied unsubscribe data into the supplied buffer, ready for sending
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param buflen the length in bytes of the data in the supplied buffer
  * @param dup integer - the MQTT dup flag
  * @param packetid integer - the MQTT packet identifier
  * @param count - number of members in the topicFilters array
  * @param topicFilters - array of topic filter names
  * @return the length of the serialized data.  <= 0 indicates error
  */
#if defined(MQTTV5)
int32_t MQTTSerialize_unsubscribe(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned short packetid,
	int count, MQTTString topicFilters[])
{
	return MQTTV5Serialize_unsubscribe(buf, buflen, dup, packetid, NULL, count, topicFilters);
}

int32_t MQTTV5Serialize_unsubscribe(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned short packetid,
			MQTTProperties* properties, int count, MQTTString topicFilters[])
#else
int32_t MQTTSerialize_unsubscribe(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned short packetid,
		int count, MQTTString topicFilters[])
#endif
{
	unsigned char *ptr = buf;
	MQTTHeader header = {0};
	int32_t rem_len = 0;
	int32_t rc = -1;
	int i = 0;

	FUNC_ENTRY;
#if defined(MQTTV5)
	if (MQTTPacket_len(rem_len = MQTTSerialize_unsubscribeLength(count, topicFilters, properties)) > buflen)
#else
	if (MQTTPacket_len(rem_len = MQTTSerialize_unsubscribeLength(count, topicFilters)) > buflen)
#endif
	{
		rc = MQTTPACKET_BUFFER_TOO_SHORT;
		goto exit;
	}

	header.byte = 0;
	header.bits.type = UNSUBSCRIBE;
	header.bits.dup = dup;
	header.bits.qos = 1;
	writeChar(&ptr, header.byte); /* write header */

	ptr += MQTTPacket_encode(ptr, rem_len); /* write remaining length */;

	writeInt(&ptr, packetid);

#if defined(MQTTV5)
	if (properties && MQTTProperties_write(&ptr, properties) < 0)
		goto exit;
#endif

	for (i = 0; i < count; ++i)
		writeMQTTString(&ptr, topicFilters[i]);

	rc = ptr - buf;
exit:
	FUNC_EXIT_RC(rc);
	return rc;
}


/**
  * Deserializes the supplied (wire) buffer into unsuback data
  * @param packetid returned integer - the MQTT packet identifier
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param buflen the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success, 0 is failure
  */
#if defined(MQTTV5)
int32_t MQTTDeserialize_unsuback(unsigned short* packetid, unsigned char* buf, int32_t buflen)
{
	return MQTTV5Deserialize_unsuback(packetid, NULL, 0, 0, NULL, buf, buflen);
}

int32_t MQTTV5Deserialize_unsuback(unsigned short* packetid, MQTTProperties* properties,
		int maxcount, int* count, unsigned char* reasonCodes, unsigned char* buf, int32_t buflen)
#else
int32_t MQTTDeserialize_unsuback(unsigned short* packetid, unsigned char* buf, int32_t buflen)
#endif
{
#if !defined(MQTTV5)
	unsigned char type = 0;
	unsigned char dup = 0;
#endif
	int32_t rc = 0;

	FUNC_ENTRY;
#if defined(MQTTV5)
  rc = MQTTV5Deserialize_subunsuback(UNSUBACK, packetid, properties,
		                       maxcount, count, reasonCodes, buf, buflen);
#else
	rc = MQTTDeserialize_ack(&type, &dup, packetid, buf, buflen);
	if (type == UNSUBACK)
		rc = 1;
#endif
	FUNC_EXIT_RC(rc);
	return rc;
}
