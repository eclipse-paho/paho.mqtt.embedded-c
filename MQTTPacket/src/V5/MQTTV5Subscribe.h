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

#ifndef MQTTV5SUBSCRIBE_H_
#define MQTTV5SUBSCRIBE_H_

#if !defined(DLLImport)
  #define DLLImport
#endif
#if !defined(DLLExport)
  #define DLLExport
#endif

typedef struct MQTTSubscribe_options
{
	unsigned char noLocal; /* 0 or 1 */
	unsigned char retainAsPublished; /* 0 or 1 */
	unsigned char retainHandling; /* 0, 1 or 2 */
} MQTTSubscribe_options;

DLLExport int32_t MQTTV5Serialize_subscribe(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned short packetid,
	MQTTProperties* properties, int count, MQTTString topicFilters[], unsigned char requestedQoSs[], MQTTSubscribe_options options[]);

DLLExport int32_t MQTTV5Deserialize_subscribe(unsigned char* dup, unsigned short* packetid, MQTTProperties* properties,
	int maxcount, int* count, MQTTString topicFilters[], unsigned char requestedQoSs[], MQTTSubscribe_options options[],
  unsigned char* buf, int len);

DLLExport int32_t MQTTV5Serialize_suback(unsigned char* buf, int32_t buflen, unsigned short packetid,
  MQTTProperties* properties, int count, unsigned char* reasonCodes);

DLLExport int32_t MQTTV5Deserialize_suback(unsigned short* packetid, MQTTProperties* properties,
  int maxcount, int* count, unsigned char* reasonCodes, unsigned char* buf, int32_t len);


#endif /* MQTTV5SUBSCRIBE_H_ */
