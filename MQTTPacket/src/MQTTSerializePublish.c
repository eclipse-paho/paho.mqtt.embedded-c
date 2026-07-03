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
 *    Ian Craggs - fix for https://bugs.eclipse.org/bugs/show_bug.cgi?id=453144
 *    Ian Craggs - MQTT v5 support
 *******************************************************************************/

#if defined(MQTTV5)
#include "V5/MQTTV5Packet.h"
#else
#include "MQTTPacket.h"
#endif

#include "StackTrace.h"

#include <string.h>


/**
  * Determines the length of the MQTT publish packet that would be produced using the supplied parameters
  * @param qos the MQTT QoS of the publish (packetid is omitted for QoS 0)
  * @param topicName the topic name to be used in the publish
  * @param payloadlen the length of the payload to be sent
  * @return the length of buffer needed to contain the serialized version of the packet
  */
#if defined(MQTTV5)
int32_t MQTTV5Serialize_publishLength(int qos, MQTTString topicName, int payloadlen, MQTTProperties* properties)
#else
int32_t MQTTSerialize_publishLength(int qos, MQTTString topicName, int payloadlen)
#endif
{
	int32_t len = 0;

	len += 2 + MQTTstrlen(topicName) + payloadlen;
	if (qos > 0)
		len += 2; /* packetid */
#if defined(MQTTV5)
	if (properties)
		len += MQTTProperties_len(properties);
#endif
	return len;
}


/**
  * Serializes the supplied publish data into the supplied buffer, ready for sending
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied buffer
  * @param dup integer - the MQTT dup flag
  * @param qos integer - the MQTT QoS value
  * @param retained integer - the MQTT retained flag
  * @param packetid integer - the MQTT packet identifier
  * @param topicName MQTTString - the MQTT topic in the publish
  * @param payload byte buffer - the MQTT publish payload
  * @param payloadlen integer - the length of the MQTT payload
  * @return the length of the serialized data.  <= 0 indicates error
  */
#if defined(MQTTV5)
int32_t MQTTSerialize_publish(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned char qos, unsigned char retained, unsigned short packetid,
		MQTTString topicName, unsigned char* payload, int32_t payloadlen)
{
  return MQTTV5Serialize_publish(buf, buflen, dup, qos, retained, packetid, topicName, NULL, payload, payloadlen);
}

int32_t MQTTV5Serialize_publish(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned char qos, unsigned char retained, unsigned short packetid,
		MQTTString topicName, MQTTProperties* properties, unsigned char* payload, int payloadlen)
#else
int32_t MQTTSerialize_publish(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned char qos, unsigned char retained, unsigned short packetid,
		MQTTString topicName, unsigned char* payload, int32_t payloadlen)
#endif
{
	unsigned char *ptr = buf;
	MQTTHeader header = {0};
	int32_t rem_len = 0;
	int32_t rc = 0;

	FUNC_ENTRY;
#if defined(MQTTV5)
	if (MQTTPacket_len(rem_len = MQTTV5Serialize_publishLength(qos, topicName, payloadlen, properties)) > buflen)
#else
	if (MQTTPacket_len(rem_len = MQTTSerialize_publishLength(qos, topicName, payloadlen)) > buflen)
#endif
	{
		rc = MQTTPACKET_BUFFER_TOO_SHORT;
		goto exit;
	}

	header.bits.type = PUBLISH;
	header.bits.dup = dup;
	header.bits.qos = qos;
	header.bits.retain = retained;
	writeChar(&ptr, header.byte); /* write header */

	ptr += MQTTPacket_encode(ptr, rem_len); /* write remaining length */;

	writeMQTTString(&ptr, topicName);

	if (qos > 0)
		writeInt(&ptr, packetid);

#if defined(MQTTV5)
  if (properties && MQTTProperties_write(&ptr, properties) < 0)
		goto exit;
#endif

	memcpy(ptr, payload, payloadlen);
	ptr += payloadlen;

	rc = ptr - buf;

exit:
	FUNC_EXIT_RC(rc);
	return rc;
}



/**
  * Serializes the ack packet into the supplied buffer.
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied buffer
  * @param type the MQTT packet type
  * @param dup the MQTT dup flag
  * @param packetid the MQTT packet identifier
  * @return serialized length, or error if 0
  */
#if defined(MQTTV5)
int32_t MQTTV5Serialize_ack(unsigned char* buf, int32_t buflen, unsigned char packettype, unsigned char dup, unsigned short packetid,
	unsigned char reasonCode, MQTTProperties* properties);

int32_t MQTTSerialize_ack(unsigned char* buf, int32_t buflen, unsigned char packettype, unsigned char dup, unsigned short packetid)
{
	return MQTTV5Serialize_ack(buf, buflen, packettype, dup, packetid, -1, NULL);
}

int32_t MQTTV5Serialize_ack(unsigned char* buf, int32_t buflen, unsigned char packettype, unsigned char dup, unsigned short packetid,
	unsigned char reasonCode, MQTTProperties* properties)
#else
int32_t MQTTSerialize_ack(unsigned char* buf, int32_t buflen, unsigned char packettype, unsigned char dup, unsigned short packetid)
#endif
{
	MQTTHeader header = {0};
	int32_t rc = 0;
	unsigned char *ptr = buf;
	int32_t len = 2;

	FUNC_ENTRY;
#if defined(MQTTV5)
  if (reasonCode >= 0)
	{
		len += 1;
		if (properties)
		  len += MQTTProperties_len(properties);
	}
#endif
	if (buflen < 4)
	{
		rc = MQTTPACKET_BUFFER_TOO_SHORT;
		goto exit;
	}
	header.bits.type = packettype;
	header.bits.dup = dup;
	header.bits.qos = (packettype == PUBREL) ? 1 : 0;
	writeChar(&ptr, header.byte); /* write header */

	ptr += MQTTPacket_encode(ptr, len); /* write remaining length */
	writeInt(&ptr, packetid);

#if defined(MQTTV5)
  if (reasonCode >= 0)
	{
		writeChar(&ptr, reasonCode);
    if (properties && MQTTProperties_write(&ptr, properties) < 0)
		  goto exit;
	}
#endif

	rc = ptr - buf;
exit:
	FUNC_EXIT_RC(rc);
	return rc;
}


/**
  * Serializes a puback packet into the supplied buffer.
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied buffer
  * @param packetid integer - the MQTT packet identifier
  * @return serialized length, or error if 0
  */
#if defined(MQTTV5)
int32_t MQTTSerialize_puback(unsigned char* buf, int32_t buflen, unsigned short packetid)
{
	return MQTTV5Serialize_puback(buf, buflen, packetid, -1, NULL);
}

int32_t MQTTV5Serialize_puback(unsigned char* buf, int32_t buflen, unsigned short packetid,
	  unsigned char reasonCode, MQTTProperties* properties)
#else
int32_t MQTTSerialize_puback(unsigned char* buf, int32_t buflen, unsigned short packetid)
#endif
{
#if defined(MQTTV5)
	return MQTTV5Serialize_ack(buf, buflen, PUBACK, 0, packetid, reasonCode, properties);
#else
	return MQTTSerialize_ack(buf, buflen, PUBACK, 0, packetid);
#endif
}

/**
  * Serializes a pubrec packet into the supplied buffer.
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied buffer
  * @param dup integer - the MQTT dup flag
  * @param packetid integer - the MQTT packet identifier
  * @return serialized length, or error if 0
  */
#if defined(MQTTV5)
int32_t MQTTSerialize_pubrec(unsigned char* buf, int32_t buflen, unsigned short packetid)
{
	return MQTTV5Serialize_pubrec(buf, buflen, packetid, -1, NULL);
}

int32_t MQTTV5Serialize_pubrec(unsigned char* buf, int32_t buflen, unsigned short packetid,
	  unsigned char reasonCode, MQTTProperties* properties)
#else
int32_t MQTTSerialize_pubrec(unsigned char* buf, int32_t buflen, unsigned short packetid)
#endif
{
#if defined(MQTTV5)
	return MQTTV5Serialize_ack(buf, buflen, PUBREC, 0, packetid, reasonCode, properties);
#else
	return MQTTSerialize_ack(buf, buflen, PUBREC, 0, packetid);
#endif
}


/**
  * Serializes a pubrel packet into the supplied buffer.
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied buffer
  * @param dup integer - the MQTT dup flag
  * @param packetid integer - the MQTT packet identifier
  * @return serialized length, or error if 0
  */
#if defined(MQTTV5)
int32_t MQTTSerialize_pubrel(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned short packetid)
{
	return MQTTV5Serialize_pubrel(buf, buflen, dup, packetid, -1, NULL);
}

int32_t MQTTV5Serialize_pubrel(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned short packetid,
	  unsigned char reasonCode, MQTTProperties* properties)
#else
int32_t MQTTSerialize_pubrel(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned short packetid)
#endif
{
#if defined(MQTTV5)
	return MQTTV5Serialize_ack(buf, buflen, PUBREL, dup, packetid, reasonCode, properties);
#else
	return MQTTSerialize_ack(buf, buflen, PUBREL, dup, packetid);
#endif
}


/**
  * Serializes a pubcomp packet into the supplied buffer.
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied buffer
  * @param packetid integer - the MQTT packet identifier
  * @return serialized length, or error if 0
  */
#if defined(MQTTV5)
int32_t MQTTSerialize_pubcomp(unsigned char* buf, int32_t buflen, unsigned short packetid)
{
	return MQTTV5Serialize_pubcomp(buf, buflen, packetid, -1, NULL);
}

int32_t MQTTV5Serialize_pubcomp(unsigned char* buf, int32_t buflen, unsigned short packetid,
	  unsigned char reasonCode, MQTTProperties* properties)
#else
int32_t MQTTSerialize_pubcomp(unsigned char* buf, int32_t buflen, unsigned short packetid)
#endif
{
#if defined(MQTTV5)
	return MQTTV5Serialize_ack(buf, buflen, PUBCOMP, 0, packetid, reasonCode, properties);
#else
	return MQTTSerialize_ack(buf, buflen, PUBCOMP, 0, packetid);
#endif
}
