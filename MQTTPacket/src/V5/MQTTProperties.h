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


enum MQTTPropertyNames {
  MQTTPROPERTY_CODE_PAYLOAD_FORMAT_INDICATOR = 1,
  MQTTPROPERTY_CODE_MESSAGE_EXPIRY_INTERVAL = 2,
  MQTTPROPERTY_CODE_CONTENT_TYPE = 3,
  MQTTPROPERTY_CODE_RESPONSE_TOPIC = 8,
  MQTTPROPERTY_CODE_CORRELATION_DATA = 9,
  MQTTPROPERTY_CODE_SUBSCRIPTION_IDENTIFIER = 11,
  MQTTPROPERTY_CODE_SESSION_EXPIRY_INTERVAL = 17,
  MQTTPROPERTY_CODE_ASSIGNED_CLIENT_IDENTIFER = 18,
  MQTTPROPERTY_CODE_SERVER_KEEP_ALIVE = 19,
  MQTTPROPERTY_CODE_AUTHENTICATION_METHOD = 21,
  MQTTPROPERTY_CODE_AUTHENTICATION_DATA = 22,
  MQTTPROPERTY_CODE_REQUEST_PROBLEM_INFORMATION = 23,
  MQTTPROPERTY_CODE_WILL_DELAY_INTERVAL = 24,
  MQTTPROPERTY_CODE_REQUEST_RESPONSE_INFORMATION = 25,
  MQTTPROPERTY_CODE_RESPONSE_INFORMATION = 26,
  MQTTPROPERTY_CODE_SERVER_REFERENCE = 28,
  MQTTPROPERTY_CODE_REASON_STRING = 31,
  MQTTPROPERTY_CODE_RECEIVE_MAXIMUM = 33,
  MQTTPROPERTY_CODE_TOPIC_ALIAS_MAXIMUM = 34,
  MQTTPROPERTY_CODE_TOPIC_ALIAS = 35,
  MQTTPROPERTY_CODE_MAXIMUM_QOS = 36,
  MQTTPROPERTY_CODE_RETAIN_AVAILABLE = 37,
  MQTTPROPERTY_CODE_USER_PROPERTY = 38,
  MQTTPROPERTY_CODE_MAXIMUM_PACKET_SIZE = 39,
  MQTTPROPERTY_CODE_WILDCARD_SUBSCRIPTION_AVAILABLE = 40,
  MQTTPROPERTY_CODE_SUBSCRIPTION_IDENTIFIER_AVAILABLE = 41,
  MQTTPROPERTY_CODE_SHARED_SUBSCRIPTION_AVAILABLE = 42
};

enum MQTTPropertyTypes {
  MQTTPROPERTY_TYPE_BYTE,
  MQTTPROPERTY_TYPE_TWO_BYTE_INTEGER,
  MQTTPROPERTY_TYPE_FOUR_BYTE_INTEGER,
  MQTTPROPERTY_TYPE_VARIABLE_BYTE_INTEGER,
  MQTTPROPERTY_TYPE_BINARY_DATA,
  MQTTPROPERTY_TYPE_UTF_8_ENCODED_STRING,
  MQTTPROPERTY_TYPE_UTF_8_STRING_PAIR
};

typedef struct {
  MQTTLenString key;
  MQTTLenString val;
} MQTTStringPair;

typedef struct
{
  int identifier; /* mbi */
  union {
    char byte;
    short integer2;
    int integer4;
    MQTTLenString data;
    MQTTStringPair string_pair; /* for user properties */
  } value;
} MQTTProperty;

typedef struct MQTTProperties
{
  int count; /* number of property entries */
  int max_count;
  int length; /* mbi: byte length of all properties */
  MQTTProperty *array;  /* array of properties */
} MQTTProperties;

#define MQTTProperties_initializer {0, 0, 0, NULL}

DLLExport int MQTTProperties_len(MQTTProperties* props);

/**
 * Add the property pointer to the property array, no allocation, just a reference
 * @param props
 * @param prop
 * @return whether the write succeeded or not, number of bytes written or < 0
 */
DLLExport int MQTTProperties_add(MQTTProperties* props, MQTTProperty* prop);

DLLExport int MQTTProperties_write(unsigned char** pptr, MQTTProperties* properties);

DLLExport int MQTTProperties_read(MQTTProperties* properties, unsigned char** pptr, unsigned char* enddata);

/**
 * @brief MQTTProperty_getType returns the type of the property based on the identifier (key).
 * @param identifier the `PropertyNames` property identifier.
 * @return the `PropertyTypes` type of the property
 */
DLLExport int MQTTProperty_getType(int identifier);
