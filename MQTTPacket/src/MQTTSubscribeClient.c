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
 *    Ian Craggs - MQTT v5 implementation
 *******************************************************************************/

#if defined(MQTTV5)
#include "V5/MQTTV5Packet.h"
#else
#include "MQTTPacket.h"
#endif

#include "StackTrace.h"

#include <string.h>

/**
  * Determines the length of the MQTT subscribe packet that would be produced using the supplied parameters
  * @param count the number of topic filter strings in topicFilters
  * @param topicFilters the array of topic filter strings to be used in the publish
  * @return the length of buffer needed to contain the serialized version of the packet
  */
#if defined(MQTTV5)
int32_t MQTTSerialize_subscribeLength(int count, MQTTString topicFilters[], MQTTProperties* properties)
#else
int32_t MQTTSerialize_subscribeLength(int count, MQTTString topicFilters[])
#endif
{
	int i;
	int32_t len = 2; /* packetid */

	for (i = 0; i < count; ++i)
		len += 2 + MQTTstrlen(topicFilters[i]) + 1; /* length + topic + req_qos */
#if defined(MQTTV5)
  if (properties)
	  len += MQTTProperties_len(properties);
#endif
	return len;
}


/**
  * Serializes the supplied subscribe data into the supplied buffer, ready for sending
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied bufferr
  * @param dup integer - the MQTT dup flag
  * @param packetid integer - the MQTT packet identifier
  * @param count - number of members in the topicFilters and reqQos arrays
  * @param topicFilters - array of topic filter names
  * @param requestedQoSs - array of requested QoS
  * @return the length of the serialized data.  <= 0 indicates error
  */
#if defined(MQTTV5)
int32_t MQTTSerialize_subscribe(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned short packetid, int count,
		MQTTString topicFilters[], unsigned char requestedQoSs[])
{
	/* need to pack requestedQoSs into subscribeOptions */
	return MQTTV5Serialize_subscribe(buf, buflen, dup, packetid, NULL, count, topicFilters, requestedQoSs, NULL);
}

int32_t MQTTV5Serialize_subscribe(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned short packetid,
		MQTTProperties* properties, int count, MQTTString topicFilters[], unsigned char requestedQoSs[], MQTTSubscribe_options options[])
#else
int32_t MQTTSerialize_subscribe(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned short packetid, int count,
		MQTTString topicFilters[], unsigned char requestedQoSs[])
#endif
{
	unsigned char *ptr = buf;
	MQTTHeader header = {0};
	int32_t rem_len = 0;
	int32_t rc = 0;
	int i = 0;

	FUNC_ENTRY;
#if defined(MQTTV5)
	if (MQTTPacket_len(rem_len = MQTTSerialize_subscribeLength(count, topicFilters, properties)) > buflen)
#else
	if (MQTTPacket_len(rem_len = MQTTSerialize_subscribeLength(count, topicFilters)) > buflen)
#endif
	{
		rc = MQTTPACKET_BUFFER_TOO_SHORT;
		goto exit;
	}

	header.byte = 0;
	header.bits.type = SUBSCRIBE;
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
	{
		unsigned char opts = requestedQoSs[i];
#if defined(MQTTV5)
		if (options)
		{
			opts |= (options[i].noLocal << 2); /* 1 bit */
			opts |= (options[i].retainAsPublished << 3); /* 1 bit */
			opts |= (options[i].retainHandling << 4); /* 2 bits */
		}
#endif
		writeMQTTString(&ptr, topicFilters[i]);
		writeChar(&ptr, opts);
	}

	rc = ptr - buf;
exit:
	FUNC_EXIT_RC(rc);
	return rc;
}



/**
  * Deserializes the supplied (wire) buffer into suback data
  * @param packetid returned integer - the MQTT packet identifier
  * @param maxcount - the maximum number of members allowed in the grantedQoSs array
  * @param count returned integer - number of members in the grantedQoSs array
  * @param grantedQoSs returned array of integers - the granted qualities of service
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param buflen the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success, 0 is failure
  */
#if defined(MQTTV5)
int32_t MQTTDeserialize_suback(unsigned short* packetid, int maxcount, int* count, unsigned char grantedQoSs[],
	unsigned char* buf, int32_t buflen)
{
	return MQTTV5Deserialize_suback(packetid, NULL, maxcount, count, grantedQoSs, buf, buflen);
}

int32_t MQTTV5Deserialize_suback(unsigned short* packetid, MQTTProperties* properties,
	  int maxcount, int* count, unsigned char* reasonCodes, unsigned char* buf, int32_t buflen)
{
	return MQTTV5Deserialize_subunsuback(SUBACK, packetid, properties,
		maxcount, count, reasonCodes, buf, buflen);
}

int32_t MQTTV5Deserialize_subunsuback(int type, unsigned short* packetid, MQTTProperties* properties,
	  int maxcount, int* count, unsigned char* reasonCodes, unsigned char* buf, int32_t buflen)
#else
int32_t MQTTDeserialize_suback(unsigned short* packetid, int maxcount, int* count, unsigned char grantedQoSs[],
	unsigned char* buf, int32_t buflen)
#endif
{
	MQTTHeader header = {0};
	unsigned char* curdata = buf;
	unsigned char* enddata = NULL;
	int32_t rc = 0;
	int32_t mylen;

	FUNC_ENTRY;
	header.byte = readChar(&curdata);
#if defined(MQTTV5)
	if (header.bits.type != type)
#else
	if (header.bits.type != SUBACK)
#endif
		goto exit;

	curdata += (rc = MQTTPacket_decodeBuf(curdata, &mylen)); /* read remaining length */
	enddata = curdata + mylen;
	if (enddata - curdata < 2)
		goto exit;

	*packetid = readInt(&curdata);

#if defined(MQTTV5)
	if (properties && !MQTTProperties_read(properties, &curdata, enddata))
	  goto exit;
#endif
  if (maxcount > 0)
	{
	  *count = 0;
	  while (curdata < enddata)
	  {
	  	if (*count > maxcount)
		{
			  rc = -1;
			  goto exit;
	  	}
#if defined(MQTTV5)
      reasonCodes[(*count)++]
#else
		  grantedQoSs[(*count)++]
#endif
                              = (unsigned char)readChar(&curdata);
	  }
  }
	rc = 1;
exit:
	FUNC_EXIT_RC(rc);
	return (int) rc;
}
