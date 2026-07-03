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
  * Deserializes the supplied (wire) buffer into unsubscribe data
  * @param dup integer returned - the MQTT dup flag
  * @param packetid integer returned - the MQTT packet identifier
  * @param maxcount - the maximum number of members allowed in the topicFilters and requestedQoSs arrays
  * @param count - number of members in the topicFilters and requestedQoSs arrays
  * @param topicFilters - array of topic filter names
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param buflen the length in bytes of the data in the supplied buffer
  * @return the length of the serialized data.  <= 0 indicates error
  */
#if defined(MQTTV5)
int32_t MQTTDeserialize_unsubscribe(unsigned char* dup, unsigned short* packetid, int maxcount, int* count, MQTTString topicFilters[],
	unsigned char* buf, int32_t len)
{
  return MQTTV5Deserialize_unsubscribe(dup, packetid, NULL, maxcount, count, topicFilters, buf, len);
}

DLLExport int32_t MQTTV5Deserialize_unsubscribe(unsigned char* dup, unsigned short* packetid, MQTTProperties* properties,
	int maxcount, int* count, MQTTString topicFilters[], unsigned char* buf, int32_t len)
#else
int32_t MQTTDeserialize_unsubscribe(unsigned char* dup, unsigned short* packetid, int maxcount, int* count, MQTTString topicFilters[],
	unsigned char* buf, int32_t len)
#endif
{
	MQTTHeader header = {0};
	unsigned char* curdata = buf;
	unsigned char* enddata = NULL;
	int32_t rc = 0;
	int32_t mylen = 0;
	int lenlen = 0;

	FUNC_ENTRY;
	header.byte = readChar(&curdata);
	if (header.bits.type != UNSUBSCRIBE)
		goto exit;
	*dup = header.bits.dup;

	if ((lenlen = MQTTPacket_decodeBuf(curdata, &mylen)) < 0) /* read remaining length */
		goto exit;

	curdata += lenlen; /* move pointer after remaining length field */
	enddata = curdata + mylen;

	*packetid = readInt(&curdata);

#if defined(MQTTV5)
	if (properties)
	{
		if (enddata == curdata)
			properties->length = properties->count = 0; /* signal that no properties were received */
		else if (!MQTTProperties_read(properties, &curdata, enddata))
			goto exit;
	}
#endif

	*count = 0;
	while (curdata < enddata)
	{
		if (!readMQTTLenString(&topicFilters[*count], &curdata, enddata))
			goto exit;
		(*count)++;
	}

	rc = 1;
exit:
	FUNC_EXIT_RC(rc);
	return (int) rc;
}


/**
  * Serializes the supplied unsuback data into the supplied buffer, ready for sending
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied buffer
  * @param packetid integer - the MQTT packet identifier
  * @return the length of the serialized data.  <= 0 indicates error
  */
#if defined(MQTTV5)
int32_t MQTTSerialize_unsuback(unsigned char* buf, int32_t buflen, unsigned short packetid)
{
	return MQTTV5Serialize_unsuback(buf, buflen, packetid, NULL, 0, NULL);
}

int32_t MQTTV5Serialize_unsuback(unsigned char* buf, int32_t buflen, unsigned short packetid,
  MQTTProperties* properties, int count, unsigned char* reasonCodes)
#else
int32_t MQTTSerialize_unsuback(unsigned char* buf, int32_t buflen, unsigned short packetid)
#endif
{
	MQTTHeader header = {0};
	int32_t rc = 0;
	unsigned char *ptr = buf;
	int32_t len = 2;
#if defined(MQTTV5)
	int i = 0;
#endif

	FUNC_ENTRY;
#if defined(MQTTV5)
	if (properties)
	  len += MQTTProperties_len(properties);
	len += count;
#endif
	if (buflen < len)
	{
		rc = MQTTPACKET_BUFFER_TOO_SHORT;
		goto exit;
	}
	header.byte = 0;
	header.bits.type = UNSUBACK;
	writeChar(&ptr, header.byte); /* write header */

	ptr += MQTTPacket_encode(ptr, len); /* write remaining length */

	writeInt(&ptr, packetid);

#if defined(MQTTV5)
	if (properties && MQTTProperties_write(&ptr, properties) < 0)
		goto exit;

  if (reasonCodes)
	{
    for (i = 0; i < count; ++i)
	    writeChar(&ptr, reasonCodes[i]);
	}
#endif

	rc = ptr - buf;
exit:
	FUNC_EXIT_RC(rc);
	return rc;
}
