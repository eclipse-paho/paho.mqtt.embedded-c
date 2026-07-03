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

#if !defined(MQTTV5PUBLISH_H_)
#define MQTTV5PUBLISH_H_

#if !defined(DLLImport)
  #define DLLImport
#endif
#if !defined(DLLExport)
  #define DLLExport
#endif

#include "MQTTPublish.h"

DLLExport int32_t MQTTV5Serialize_publish(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned char qos, unsigned char retained,
  unsigned short packetid, MQTTString topicName, MQTTProperties* props, unsigned char* payload, int32_t payloadlen);

DLLExport int32_t MQTTV5Deserialize_publish(unsigned char* dup, unsigned char* qos, unsigned char* retained, unsigned short* packetid, MQTTString* topicName,
		MQTTProperties* props, unsigned char** payload, int32_t* payloadlen, unsigned char* buf, int32_t len);

DLLExport int MQTTV5Serialize_puback(unsigned char* buf, int32_t buflen, unsigned short packetid,
  unsigned char reasonCode, MQTTProperties* properties);

DLLExport int32_t MQTTV5Serialize_pubrec(unsigned char* buf, int32_t buflen, unsigned short packetid,
  unsigned char reasonCode, MQTTProperties* properties);

DLLExport int32_t MQTTV5Serialize_pubrel(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned short packetid,
  unsigned char reasonCode, MQTTProperties* properties);

DLLExport int32_t MQTTV5Serialize_pubcomp(unsigned char* buf, int32_t buflen, unsigned short packetid,
  unsigned char reasonCode, MQTTProperties* properties);

int32_t MQTTV5Deserialize_ack(unsigned char* packettype, unsigned char* dup, unsigned short* packetid,
	unsigned char *reasonCode, MQTTProperties* properties, unsigned char* buf, int32_t buflen);

#endif /* MQTTV5PUBLISH_H_ */
