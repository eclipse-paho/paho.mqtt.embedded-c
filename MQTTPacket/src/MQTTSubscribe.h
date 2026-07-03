/*******************************************************************************
 * Copyright (c) 2014, 2026 IBM Corp., Ian Craggs
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
 *    Xiang Rong - 442039 Add makefile to Embedded C client
 *******************************************************************************/

#ifndef MQTTSUBSCRIBE_H_
#define MQTTSUBSCRIBE_H_

#if !defined(DLLImport)
  #define DLLImport
#endif
#if !defined(DLLExport)
  #define DLLExport
#endif

DLLExport int32_t MQTTSerialize_subscribe(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned short packetid,
		int count, MQTTString topicFilters[], unsigned char requestedQoSs[]);

DLLExport int32_t MQTTDeserialize_subscribe(unsigned char* dup, unsigned short* packetid,
		int maxcount, int* count, MQTTString topicFilters[], unsigned char requestedQoSs[], unsigned char* buf, int32_t len);

DLLExport int32_t MQTTSerialize_suback(unsigned char* buf, int32_t buflen, unsigned short packetid, int count, unsigned char* grantedQoSs);

DLLExport int32_t MQTTDeserialize_suback(unsigned short* packetid, int maxcount, int* count, unsigned char grantedQoSs[], unsigned char* buf, int32_t len);


#endif /* MQTTSUBSCRIBE_H_ */
