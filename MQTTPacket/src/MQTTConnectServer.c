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
 *    Ian Craggs - add MQTT v5 support
 *******************************************************************************/

#include "StackTrace.h"
#if defined(MQTTV5)
#include "V5/MQTTV5Packet.h"
#else
#include "MQTTPacket.h"
#endif
#include <string.h>

#define min(a, b) ((a < b) ? a : b)


/**
  * Validates MQTT protocol name and version combinations
  * @param protocol the MQTT protocol name as an MQTTString
  * @param version the MQTT protocol version number, as in the connect packet
  * @return correct MQTT combination?  1 is true, 0 is false
  */
int MQTTPacket_checkVersion(MQTTString* protocol, int version)
{
	int rc = 0;

	if (version == 3 && memcmp(protocol->lenstring.data, "MQIsdp",
			min(6, protocol->lenstring.len)) == 0)
		rc = 1;
	else if (version == 4 && memcmp(protocol->lenstring.data, "MQTT",
			min(4, protocol->lenstring.len)) == 0)
		rc = 1;
#if defined(MQTTV5)
  else if (version == 5 && memcmp(protocol->lenstring.data, "MQTT",
		  min(4, protocol->lenstring.len)) == 0)
	  rc = 1;
#endif
	return rc;
}



#if defined(MQTTV5)
int32_t MQTTDeserialize_connect(MQTTPacket_connectData* data, unsigned char* buf, int32_t len)
{
	return MQTTV5Deserialize_connect(NULL, NULL, data, buf, len);
}

/**
  * Deserializes the supplied (wire) buffer into connect data structure
  * @param willProperties the V5 properties to be applied to the will message, if it exists
  * @param connectProperties the V5 properties for the connect packet
  * @param data the connect data structure to be filled out
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param len the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success, 0 is failure
  */
int32_t MQTTV5Deserialize_connect(MQTTProperties* willProperties, MQTTProperties* connectProperties,
	MQTTPacket_connectData* data, unsigned char* buf, int32_t len)
#else
/**
  * Deserializes the supplied (wire) buffer into connect data structure
  * @param data the connect data structure to be filled out
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param len the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success, 0 is failure
  */
int32_t MQTTDeserialize_connect(MQTTPacket_connectData* data, unsigned char* buf, int32_t len)
#endif
{
	MQTTHeader header = {0};
	MQTTConnectFlags flags = {0};
	unsigned char* curdata = buf;
	unsigned char* enddata = &buf[len];
	int32_t rc = 0;
	MQTTString Protocol;
	int32_t mylen = 0;
	int lenlen = 0;

	FUNC_ENTRY;
	header.byte = readChar(&curdata);
	if (header.bits.type != CONNECT)
		goto exit;

	if ((lenlen = MQTTPacket_decodeBuf(curdata, &mylen)) < 0) /* read remaining length */
		goto exit;

	curdata += lenlen; /* move pointer after remaining length field */

	if (!readMQTTLenString(&Protocol, &curdata, enddata) ||
		enddata - curdata < 0) /* do we have enough data to read the protocol version byte? */
		goto exit;

	data->MQTTVersion = (int)readChar(&curdata); /* Protocol version */
	/* If we don't recognize the protocol version, we don't parse the connect packet on the
	 * basis that we don't know what the format will be.
	 */
	if (MQTTPacket_checkVersion(&Protocol, data->MQTTVersion))
	{
		flags.all = readChar(&curdata);
		data->cleansession = flags.bits.cleansession;
		data->keepAliveInterval = readInt(&curdata);
		#if defined(MQTTV5)
		if (data->MQTTVersion == 5)
		{
		  if (!MQTTProperties_read(connectProperties, &curdata, enddata))
			  goto exit;
		}
		#endif
		if (!readMQTTLenString(&data->clientID, &curdata, enddata))
			goto exit;
		data->willFlag = flags.bits.will;
		if (flags.bits.will)
		{
			#if defined(MQTTV5)
			if (data->MQTTVersion == 5)
			{
				if (!MQTTProperties_read(willProperties, &curdata, enddata))
				  goto exit;
			}
			#endif
			data->will.qos = flags.bits.willQoS;
			data->will.retained = flags.bits.willRetain;
			if (!readMQTTLenString(&data->will.topicName, &curdata, enddata) ||
				  !readMQTTLenString(&data->will.message, &curdata, enddata))
				goto exit;
		}
		if (flags.bits.username)
		{
			if (enddata - curdata < 3 || !readMQTTLenString(&data->username, &curdata, enddata))
				goto exit; /* username flag set, but no username supplied - invalid */
			if (flags.bits.password &&
				(enddata - curdata < 3 || !readMQTTLenString(&data->password, &curdata, enddata)))
				goto exit; /* password flag set, but no password supplied - invalid */
		}
		else if (flags.bits.password)
			goto exit; /* password flag set without username - invalid */
		rc = 1;
	}
exit:
	FUNC_EXIT_RC(rc);
	return rc;
}


/**
  * Serializes the connack packet into the supplied buffer.
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied buffer
  * @param connack_rc the integer connack return code to be used
  * @param sessionPresent the MQTT 3.1.1 sessionPresent flag
	* @param connackProperties MQTT v5 properties, if NULL, then MQTT 3.1.1 connack
  * @return serialized length, or error if 0
  */
#if defined(MQTTV5)
int32_t MQTTSerialize_connack(unsigned char* buf, int32_t buflen, unsigned char connack_rc, unsigned char sessionPresent)
{
	return MQTTV5Serialize_connack(buf, buflen, connack_rc, sessionPresent, NULL);
}

int32_t MQTTV5Serialize_connack(unsigned char* buf, int32_t buflen, unsigned char connack_rc, unsigned char sessionPresent,
  MQTTProperties* connackProperties)
#else
int32_t MQTTSerialize_connack(unsigned char* buf, int32_t buflen, unsigned char connack_rc, unsigned char sessionPresent)
#endif
{
	MQTTHeader header = {0};
	int32_t rc = 0;
	unsigned char *ptr = buf;
	MQTTConnackFlags flags = {0};
	int32_t len = 0;

	FUNC_ENTRY;

#if defined(MQTTV5)
	len = 2 + (connackProperties == NULL ? 0 : connackProperties->length);
#else
	len = 2;
#endif

	if (MQTTPacket_len(len) > buflen)
	{
		rc = MQTTPACKET_BUFFER_TOO_SHORT;
		goto exit;
	}
	header.byte = 0;
	header.bits.type = CONNACK;
	writeChar(&ptr, header.byte); /* write header */

	ptr += MQTTPacket_encode(ptr, len); /* write remaining length */

	flags.all = 0;
	flags.bits.sessionpresent = sessionPresent;
	writeChar(&ptr, flags.all);
	writeChar(&ptr, connack_rc);

#if defined(MQTTV5)
	if (connackProperties && MQTTProperties_write(&ptr, connackProperties) < 0)
		goto exit;
#endif

	rc = ptr - buf;
exit:
	FUNC_EXIT_RC(rc);
	return rc;
}


#if defined(MQTTV5)
int32_t MQTTV5Deserialize_zero(unsigned char packettype, MQTTProperties* properties, unsigned char* reasonCode,
	    unsigned char* buf, int32_t buflen)
{
	MQTTHeader header = {0};
	unsigned char* curdata = buf;
	unsigned char* enddata = NULL;
	int32_t rc = 0;
	int32_t mylen;
	int lenlen = 0;

	FUNC_ENTRY;
	header.byte = readChar(&curdata);
	if (header.bits.type != packettype)
		goto exit;

	if ((lenlen = MQTTPacket_decodeBuf(curdata, &mylen)) < 0) /* read remaining length */
		goto exit;

	curdata += lenlen; /* move pointer after remaining length field */
	enddata = curdata + mylen;

	if (mylen > 0)
	{
		*reasonCode = (unsigned char)readChar(&curdata);
		if (mylen > 1 && !MQTTProperties_read(properties, &curdata, enddata))
			goto exit;
	}

	rc = 1;
exit:
	FUNC_EXIT_RC(rc);
	return rc;
}
#endif

/**
  * Deserializes the supplied (wire) buffer into connack data - return code
  * @param sessionPresent the session present flag returned (only for MQTT 3.1.1)
  * @param connack_rc returned integer value of the connack return code
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param len the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success, 0 is failure
  */
#if defined(MQTTV5)
int32_t MQTTV5Deserialize_disconnect(MQTTProperties* properties, unsigned char* reasonCode,
	    unsigned char* buf, int32_t buflen)
{
	return MQTTV5Deserialize_zero(DISCONNECT, properties, reasonCode, buf, buflen);
}

int32_t MQTTV5Deserialize_auth(MQTTProperties* properties, unsigned char* reasonCode,
	    unsigned char* buf, int32_t buflen)
{
	return MQTTV5Deserialize_zero(AUTH, properties, reasonCode, buf, buflen);
}
#endif

int32_t MQTTDeserialize_disconnect(unsigned char* buf, int32_t buflen)
{
	unsigned char type = 0;
	unsigned char dup = 0;
	unsigned short packetid = 0;
	int32_t rc = 0;

	FUNC_ENTRY;
	rc = MQTTDeserialize_ack(&type, &dup, &packetid, buf, buflen);
	if (type == DISCONNECT)
		rc = 1;
	FUNC_EXIT_RC(rc);
	return rc;
}
