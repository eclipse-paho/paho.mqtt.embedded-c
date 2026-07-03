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

#ifndef MQTTV5PACKET_H_
#define MQTTV5PACKET_H_

#include "MQTTPacket.h"

#if defined(__cplusplus) /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

#include "MQTTReasonCodes.h"

#include "MQTTProperties.h"

#include "MQTTV5Connect.h"

#include "MQTTV5Publish.h"

#include "MQTTV5Subscribe.h"

#include "MQTTV5Unsubscribe.h"

void writeInt4(unsigned char** pptr, int anInt);
int readInt4(unsigned char** pptr);

void writeMQTTLenString(unsigned char** pptr, MQTTLenString lenstring);

int MQTTLenStringRead(MQTTLenString* lenstring, unsigned char** pptr, unsigned char* enddata);

#if defined(__cplusplus) /* If this is a C++ compiler, use C linkage */
}
#endif

#endif /* MQTTV5PACKET_H_ */
