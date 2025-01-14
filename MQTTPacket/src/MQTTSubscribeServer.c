/*******************************************************************************
 * Copyright (c) 2014, 2023 IBM Corp., Ian Craggs and others
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
 *    Ian Craggs - initial API and implementation and/or initial documentation
 *    Ian Craggs - MQTT V5.0 support
 *******************************************************************************/

#if defined(MQTTV5)
#include "V5/MQTTV5Packet.h"
#else
#include "MQTTPacket.h"
#endif
#include "StackTrace.h"

#include <string.h>


/**
  * Deserializes the supplied (wire) buffer into subscribe data
  * @param dup integer returned - the MQTT dup flag
  * @param packetid integer returned - the MQTT packet identifier
  * @param maxcount - the maximum number of members allowed in the topicFilters and requestedQoSs arrays
  * @param count - number of members in the topicFilters and requestedQoSs arrays
  * @param topicFilters - array of topic filter names
  * @param requestedQoSs - array of requested QoS
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param buflen the length in bytes of the data in the supplied buffer
  * @return the length of the serialized data.  <= 0 indicates error
  */
#if defined(MQTTV5)
int32_t MQTTDeserialize_subscribe(unsigned char* dup, unsigned short* packetid,
	int maxcount, int* count, MQTTString topicFilters[], unsigned char requestedQoSs[],
	unsigned char* buf, int32_t buflen)
{
	return MQTTV5Deserialize_subscribe(dup, packetid, NULL,
			maxcount, count, topicFilters, requestedQoSs, NULL, buf, buflen);
}

int32_t MQTTV5Deserialize_subscribe(unsigned char* dup, unsigned short* packetid, MQTTProperties* properties,
		int maxcount, int* count, MQTTString topicFilters[], unsigned char requestedQoSs[], MQTTSubscribe_options options[],
	  unsigned char* buf, int32_t buflen)
#else
int32_t MQTTDeserialize_subscribe(unsigned char* dup, unsigned short* packetid, int maxcount, int* count, MQTTString topicFilters[],
	unsigned char requestedQoSs[], unsigned char* buf, int32_t buflen)
#endif
{
	MQTTHeader header = {0};
	unsigned char* curdata = buf;
	unsigned char* enddata = NULL;
	int32_t rc = MQTTPACKET_READ_ERROR;
	int32_t mylen = 0;

	FUNC_ENTRY;
	header.byte = readChar(&curdata);
	if (header.bits.type != SUBSCRIBE)
		goto exit;
	*dup = header.bits.dup;

	rc = MQTTPacket_decodeBuf(curdata, &mylen); /* read remaining length */
	if (rc <= 0)
		goto exit;
	curdata += rc;
	rc = MQTTPACKET_READ_ERROR;
	enddata = curdata + mylen;

	*packetid = readInt(&curdata);

#if defined(MQTTV5)
	if (properties && !MQTTProperties_read(properties, &curdata, enddata))
	  goto exit;
#endif

	*count = 0;
	while (curdata < enddata)
	{
		if (*count == maxcount)
			goto exit;
		if (!readMQTTLenString(&topicFilters[*count], &curdata, enddata))
			goto exit;
		if (curdata >= enddata) /* do we have enough data to read the req_qos version byte? */
			goto exit;
		requestedQoSs[*count] = readChar(&curdata);
#if defined(MQTTV5)
    if (options)
		{
		  options[*count].noLocal = (requestedQoSs[*count] >> 2) & 0x01; /* 1 bit */
		  options[*count].retainAsPublished = (requestedQoSs[*count] >> 3) & 0x01; /* 1 bit */
      options[*count].retainHandling = (requestedQoSs[*count] >> 4) & 0x03; /* 2 bits */
	  }
		requestedQoSs[*count] &= 0x03; /* 0 all except qos bits */
#endif
		(*count)++;
	}

	rc = 1;
exit:
	FUNC_EXIT_RC(rc);
	return (int) rc;
}


/**
  * Serializes the supplied suback data into the supplied buffer, ready for sending
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied buffer
  * @param packetid integer - the MQTT packet identifier
  * @param count - number of members in the grantedQoSs array
  * @param grantedQoSs - array of granted QoS
  * @return the length of the serialized data.  <= 0 indicates error
  */
#if defined(MQTTV5)
int32_t MQTTSerialize_suback(unsigned char* buf, int32_t buflen, unsigned short packetid, int count, unsigned char* grantedQoSs)
{
	return MQTTV5Serialize_suback(buf, buflen, packetid, NULL, count, grantedQoSs);
}

int32_t MQTTV5Serialize_suback(unsigned char* buf, int32_t buflen, unsigned short packetid,
	  MQTTProperties* properties, int count, unsigned char* reasonCodes)
#else
int32_t MQTTSerialize_suback(unsigned char* buf, int32_t buflen, unsigned short packetid, int count, unsigned char* grantedQoSs)
#endif
{
	MQTTHeader header = {0};
	int32_t rc = -1;
	unsigned char *ptr = buf;
	int i;
	int32_t len = 0;

	FUNC_ENTRY;
#if defined(MQTTV5)
	if (properties)
	  len += MQTTProperties_len(properties);
#endif
  len += count + 2;
	if (buflen < len)
	{
		rc = MQTTPACKET_BUFFER_TOO_SHORT;
		goto exit;
	}
	header.byte = 0;
	header.bits.type = SUBACK;
	writeChar(&ptr, header.byte); /* write header */

	ptr += MQTTPacket_encode(ptr, len); /* write remaining length */

	writeInt(&ptr, packetid);

#if defined(MQTTV5)
  if (properties && MQTTProperties_write(&ptr, properties) < 0)
		goto exit;
#endif

	for (i = 0; i < count; ++i)
#if defined(MQTTV5)
    writeChar(&ptr, reasonCodes[i]);
#else
		writeChar(&ptr, grantedQoSs[i]);
#endif

	rc = ptr - buf;
exit:
	FUNC_EXIT_RC(rc);
	return rc;
}
