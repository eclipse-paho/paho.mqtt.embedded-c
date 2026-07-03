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

#ifndef MQTTV5UNSUBSCRIBE_H_
#define MQTTV5UNSUBSCRIBE_H_

#if !defined(DLLImport)
  #define DLLImport
#endif
#if !defined(DLLExport)
  #define DLLExport
#endif

DLLExport int32_t MQTTV5Serialize_unsubscribe(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned short packetid,
	MQTTProperties* properties, int count, MQTTString* topicFilters);

DLLExport int32_t MQTTV5Deserialize_unsubscribe(unsigned char* dup, unsigned short* packetid, MQTTProperties* properties,
	int maxcount, int* count, MQTTString* topicFilters, unsigned char* buf, int32_t len);

DLLExport int32_t MQTTV5Serialize_unsuback(unsigned char* buf, int32_t buflen, unsigned short packetid,
  MQTTProperties* properties, int count, unsigned char* reasonCodes);

DLLExport int32_t MQTTV5Deserialize_unsuback(unsigned short* packetid, MQTTProperties* properties,
  int maxcount, int* count, unsigned char* reasonCodes, unsigned char* buf, int32_t len);

int MQTTV5Deserialize_subunsuback(int type, unsigned short* packetid, MQTTProperties* properties,
  int maxcount, int* count, unsigned char* reasonCodes, unsigned char* buf, int32_t buflen);


#endif /* MQTTV5UNSUBSCRIBE_H_ */
