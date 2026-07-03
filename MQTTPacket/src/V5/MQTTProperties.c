/*******************************************************************************
 * Copyright (c) 2017, 2026 IBM Corp., Ian Craggs
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
 *******************************************************************************/

#include "MQTTV5Packet.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

struct nameToType
{
  enum MQTTPropertyNames name;
  enum MQTTPropertyTypes type;
} namesToTypes[] =
{
  {MQTTPROPERTY_CODE_PAYLOAD_FORMAT_INDICATOR, MQTTPROPERTY_TYPE_BYTE},
  {MQTTPROPERTY_CODE_MESSAGE_EXPIRY_INTERVAL, MQTTPROPERTY_TYPE_FOUR_BYTE_INTEGER},
  {MQTTPROPERTY_CODE_CONTENT_TYPE, MQTTPROPERTY_TYPE_UTF_8_ENCODED_STRING},
  {MQTTPROPERTY_CODE_RESPONSE_TOPIC, MQTTPROPERTY_TYPE_UTF_8_ENCODED_STRING},
  {MQTTPROPERTY_CODE_CORRELATION_DATA, MQTTPROPERTY_TYPE_BINARY_DATA},
  {MQTTPROPERTY_CODE_SUBSCRIPTION_IDENTIFIER, MQTTPROPERTY_TYPE_VARIABLE_BYTE_INTEGER},
  {MQTTPROPERTY_CODE_SESSION_EXPIRY_INTERVAL, MQTTPROPERTY_TYPE_FOUR_BYTE_INTEGER},
  {MQTTPROPERTY_CODE_ASSIGNED_CLIENT_IDENTIFER, MQTTPROPERTY_TYPE_UTF_8_ENCODED_STRING},
  {MQTTPROPERTY_CODE_SERVER_KEEP_ALIVE, MQTTPROPERTY_TYPE_TWO_BYTE_INTEGER},
  {MQTTPROPERTY_CODE_AUTHENTICATION_METHOD, MQTTPROPERTY_TYPE_UTF_8_ENCODED_STRING},
  {MQTTPROPERTY_CODE_AUTHENTICATION_DATA, MQTTPROPERTY_TYPE_BINARY_DATA},
  {MQTTPROPERTY_CODE_REQUEST_PROBLEM_INFORMATION, MQTTPROPERTY_TYPE_BYTE},
  {MQTTPROPERTY_CODE_WILL_DELAY_INTERVAL, MQTTPROPERTY_TYPE_FOUR_BYTE_INTEGER},
  {MQTTPROPERTY_CODE_REQUEST_RESPONSE_INFORMATION, MQTTPROPERTY_TYPE_BYTE},
  {MQTTPROPERTY_CODE_RESPONSE_INFORMATION, MQTTPROPERTY_TYPE_UTF_8_ENCODED_STRING},
  {MQTTPROPERTY_CODE_SERVER_REFERENCE, MQTTPROPERTY_TYPE_UTF_8_ENCODED_STRING},
  {MQTTPROPERTY_CODE_REASON_STRING, MQTTPROPERTY_TYPE_UTF_8_ENCODED_STRING},
  {MQTTPROPERTY_CODE_RECEIVE_MAXIMUM, MQTTPROPERTY_TYPE_TWO_BYTE_INTEGER},
  {MQTTPROPERTY_CODE_TOPIC_ALIAS_MAXIMUM, MQTTPROPERTY_TYPE_TWO_BYTE_INTEGER},
  {MQTTPROPERTY_CODE_TOPIC_ALIAS, MQTTPROPERTY_TYPE_TWO_BYTE_INTEGER},
  {MQTTPROPERTY_CODE_MAXIMUM_QOS, MQTTPROPERTY_TYPE_BYTE},
  {MQTTPROPERTY_CODE_RETAIN_AVAILABLE, MQTTPROPERTY_TYPE_BYTE},
  {MQTTPROPERTY_CODE_USER_PROPERTY, MQTTPROPERTY_TYPE_UTF_8_STRING_PAIR},
  {MQTTPROPERTY_CODE_MAXIMUM_PACKET_SIZE, MQTTPROPERTY_TYPE_FOUR_BYTE_INTEGER},
  {MQTTPROPERTY_CODE_WILDCARD_SUBSCRIPTION_AVAILABLE, MQTTPROPERTY_TYPE_BYTE},
  {MQTTPROPERTY_CODE_SUBSCRIPTION_IDENTIFIER_AVAILABLE, MQTTPROPERTY_TYPE_BYTE},
  {MQTTPROPERTY_CODE_SHARED_SUBSCRIPTION_AVAILABLE, MQTTPROPERTY_TYPE_BYTE}
};


int MQTTProperty_getType(int identifier)
{
  int i, rc = -1;

  for (i = 0; i < ARRAY_SIZE(namesToTypes); ++i)
  {
    if (namesToTypes[i].name == identifier)
    {
      rc = namesToTypes[i].type;
      break;
    }
  }
  return rc;
}


int MQTTProperties_len(MQTTProperties* props)
{
  /* properties length is an mbi */
  return props->length + MQTTPacket_VBIlen(props->length);
}


int MQTTProperties_add(MQTTProperties* props, MQTTProperty* prop)
{
  int rc = 0, type;

  if (props->count >= props->max_count)
    rc = -1;  /* max number of properties already in structure */
  else if ((type = MQTTProperty_getType(prop->identifier)) < 0)
    rc = -2;
  else
  {
    int len = 0;

    props->array[props->count++] = *prop;
    /* calculate length */
    switch (type)
    {
      case MQTTPROPERTY_TYPE_BYTE:
        len = 1;
        break;
      case MQTTPROPERTY_TYPE_TWO_BYTE_INTEGER:
        len = 2;
        break;
      case MQTTPROPERTY_TYPE_FOUR_BYTE_INTEGER:
        len = 4;
        break;
      case MQTTPROPERTY_TYPE_VARIABLE_BYTE_INTEGER:
        if (prop->value.integer4 >= 0 && prop->value.integer4 <= 127)
          len = 1;
        else if (prop->value.integer4 >= 128 && prop->value.integer4 <= 16383)
          len = 2;
        else if (prop->value.integer4 >= 16384 && prop->value.integer4 < 2097151)
          len = 3;
        else if (prop->value.integer4 >= 2097152 && prop->value.integer4 < 268435455)
          len = 4;
        break;
      case MQTTPROPERTY_TYPE_BINARY_DATA:
      case MQTTPROPERTY_TYPE_UTF_8_ENCODED_STRING:
        len = 2 + prop->value.data.len;
        break;
      case MQTTPROPERTY_TYPE_UTF_8_STRING_PAIR:
        len = 2 + prop->value.string_pair.key.len;
        len += 2 + prop->value.string_pair.val.len;
        break;
    }
    props->length += len + 1; /* add identifier byte */
  }

  return rc;
}


int MQTTProperty_write(unsigned char** pptr, MQTTProperty* prop)
{
  int rc = -1,
      type = -1;

  type = MQTTProperty_getType(prop->identifier);
  if (type >= MQTTPROPERTY_TYPE_BYTE && type <= MQTTPROPERTY_TYPE_UTF_8_STRING_PAIR)
  {
    writeChar(pptr, prop->identifier);
    switch (type)
    {
      case MQTTPROPERTY_TYPE_BYTE:
        writeChar(pptr, prop->value.byte);
        rc = 1;
        break;
      case MQTTPROPERTY_TYPE_TWO_BYTE_INTEGER:
        writeInt(pptr, prop->value.integer2);
        rc = 2;
        break;
      case MQTTPROPERTY_TYPE_FOUR_BYTE_INTEGER:
        writeInt4(pptr, prop->value.integer4);
        rc = 4;
        break;
      case MQTTPROPERTY_TYPE_VARIABLE_BYTE_INTEGER:
        rc = MQTTPacket_encode(*pptr, prop->value.integer4);
        break;
      case MQTTPROPERTY_TYPE_BINARY_DATA:
      case MQTTPROPERTY_TYPE_UTF_8_ENCODED_STRING:
        writeMQTTLenString(pptr, prop->value.data);
        rc = prop->value.data.len + 2; /* include length field */
        break;
      case MQTTPROPERTY_TYPE_UTF_8_STRING_PAIR:
        writeMQTTLenString(pptr, prop->value.string_pair.key);
        writeMQTTLenString(pptr, prop->value.string_pair.val);
        rc = prop->value.string_pair.key.len + prop->value.string_pair.val.len + 4; /* include length fields */
        break;
    }
  }
  return rc + 1; /* include identifier byte */
}


/**
 * write the supplied properties into a packet buffer
 * @param pptr pointer to the buffer - move the pointer as we add data
 * @param remlength the max length of the buffer
 * @return whether the write succeeded or not, number of bytes written or < 0
 */
int MQTTProperties_write(unsigned char** pptr, MQTTProperties* properties)
{
  int rc = -1;
  int i = 0, len = 0;

  /* write the entire property list length first */
  *pptr += MQTTPacket_encode(*pptr, properties->length);
  len = rc = 1;
  for (i = 0; i < properties->count; ++i)
  {
    rc = MQTTProperty_write(pptr, &properties->array[i]);
    if (rc < 0)
      break;
    else
      len += rc;
  }
  if (rc >= 0)
    rc = len;

  return rc;
}


int MQTTProperty_read(MQTTProperty* prop, unsigned char** pptr, unsigned char* enddata)
{
  int type = -1,
    len = 0;

  prop->identifier = (unsigned char)readChar(pptr);
  type = MQTTProperty_getType(prop->identifier);
  if (type >= MQTTPROPERTY_TYPE_BYTE && type <= MQTTPROPERTY_TYPE_UTF_8_STRING_PAIR)
  {
    switch (type)
    {
      case MQTTPROPERTY_TYPE_BYTE:
        prop->value.byte = readChar(pptr);
        len = 1;
        break;
      case MQTTPROPERTY_TYPE_TWO_BYTE_INTEGER:
        prop->value.integer2 = readInt(pptr);
        len = 2;
        break;
      case MQTTPROPERTY_TYPE_FOUR_BYTE_INTEGER:
        prop->value.integer4 = readInt4(pptr);
        len = 4;
        break;
      case MQTTPROPERTY_TYPE_VARIABLE_BYTE_INTEGER:
        len = MQTTPacket_decodeBuf(*pptr, &prop->value.integer4);
        *pptr += len;
        break;
      case MQTTPROPERTY_TYPE_BINARY_DATA:
      case MQTTPROPERTY_TYPE_UTF_8_ENCODED_STRING:
        len = MQTTLenStringRead(&prop->value.data, pptr, enddata);
        break;
      case MQTTPROPERTY_TYPE_UTF_8_STRING_PAIR:
        len = MQTTLenStringRead(&prop->value.string_pair.key, pptr, enddata);
        len += MQTTLenStringRead(&prop->value.string_pair.val, pptr, enddata);
        break;
    }
  }
  return len + 1; /* 1 byte for identifier */
}


int MQTTProperties_read(MQTTProperties* properties, unsigned char** pptr, unsigned char* enddata)
{
  int rc = 0;
  int remlength = 0;

  properties->count = 0;
	if (enddata - (*pptr) > 0) /* enough length to read the VBI? */
  {
    *pptr += MQTTPacket_decodeBuf(*pptr, &remlength);
    properties->length = remlength;
    while (properties->count < properties->max_count && remlength > 0)
    {
      remlength -= MQTTProperty_read(&properties->array[properties->count], pptr, enddata);
      properties->count++;
    }
    if (remlength == 0)
      rc = 1; /* data read successfully */
  }

  return rc;
}
