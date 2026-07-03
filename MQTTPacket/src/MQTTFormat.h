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
 *******************************************************************************/

#if !defined(MQTTFORMAT_H)
#define MQTTFORMAT_H

#include "StackTrace.h"
#include "MQTTPacket.h"

const char* MQTTPacket_getName(unsigned short packetid);
int MQTTStringFormat_connect(char* strbuf, int strbuflen, MQTTPacket_connectData* data);
int MQTTStringFormat_connack(char* strbuf, int strbuflen, unsigned char connack_rc, unsigned char sessionPresent);
int MQTTStringFormat_publish(char* strbuf, int strbuflen, unsigned char dup, int qos, unsigned char retained,
		unsigned short packetid, MQTTString topicName, unsigned char* payload, int payloadlen);
int MQTTStringFormat_ack(char* strbuf, int strbuflen, unsigned char packettype, unsigned char dup, unsigned short packetid);
int MQTTStringFormat_subscribe(char* strbuf, int strbuflen, unsigned char dup, unsigned short packetid, int count,
		MQTTString topicFilters[], unsigned char requestedQoSs[]);
int MQTTStringFormat_suback(char* strbuf, int strbuflen, unsigned short packetid, int count, unsigned char* grantedQoSs);
int MQTTStringFormat_unsubscribe(char* strbuf, int strbuflen, unsigned char dup, unsigned short packetid,
		int count, MQTTString topicFilters[]);
char* MQTTFormat_toClientString(char* strbuf, int strbuflen, unsigned char* buf, int32_t buflen);
char* MQTTFormat_toServerString(char* strbuf, int strbuflen, unsigned char* buf, int32_t buflen);

#endif
