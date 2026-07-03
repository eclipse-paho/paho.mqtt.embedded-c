/*******************************************************************************
 * Copyright (c) 2017, 2026 IBM Corp., Ian Craggs and others
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

#ifndef MQTT5CONNECT_H_
#define MQTT5CONNECT_H_

#include "MQTTConnect.h"

DLLExport int32_t MQTTV5Serialize_connect(unsigned char* buf, int32_t buflen, MQTTPacket_connectData* options,
  MQTTProperties* connectProperties, MQTTProperties* willProperties);

DLLExport int32_t MQTTV5Deserialize_connect(MQTTProperties* willProperties,
  MQTTProperties* connectProperties, MQTTPacket_connectData* data, unsigned char* buf, int32_t len);

DLLExport int32_t MQTTV5Serialize_connack(unsigned char* buf, int32_t buflen, unsigned char connack_rc,
  unsigned char sessionPresent, MQTTProperties* connackProperties);

DLLExport int32_t MQTTV5Deserialize_connack(MQTTProperties* connackProperties,
  unsigned char* sessionPresent, unsigned char* connack_rc, unsigned char* buf, int32_t buflen);

DLLExport int32_t MQTTV5Serialize_disconnect(unsigned char* buf, int32_t buflen, unsigned char reasonCode,
  MQTTProperties* properties);

DLLExport int32_t MQTTV5Deserialize_disconnect(MQTTProperties* properties, unsigned char* reasonCode,
  unsigned char* buf, int32_t buflen);

DLLExport int32_t MQTTV5Serialize_auth(unsigned char* buf, int32_t buflen, unsigned char reasonCode,
  MQTTProperties* properties);

DLLExport int32_t MQTTV5Deserialize_auth(MQTTProperties* properties, unsigned char* reasonCode,
  unsigned char* buf, int32_t buflen);

#endif /* MQTTV5CONNECT_H_ */
