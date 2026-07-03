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
 *    Xiang Rong - 442039 Add makefile to Embedded C client
 *******************************************************************************/

#ifndef MQTTUNSUBSCRIBE_H_
#define MQTTUNSUBSCRIBE_H_

#if !defined(DLLImport)
  #define DLLImport
#endif
#if !defined(DLLExport)
  #define DLLExport
#endif

DLLExport int32_t MQTTSerialize_unsubscribe(unsigned char* buf, int32_t buflen, unsigned char dup, unsigned short packetid,
		int count, MQTTString topicFilters[]);

DLLExport int32_t MQTTDeserialize_unsubscribe(unsigned char* dup, unsigned short* packetid, int max_count, int* count, MQTTString topicFilters[],
		unsigned char* buf, int32_t len);

DLLExport int32_t MQTTSerialize_unsuback(unsigned char* buf, int32_t buflen, unsigned short packetid);

DLLExport int32_t MQTTDeserialize_unsuback(unsigned short* packetid, unsigned char* buf, int32_t len);

#endif /* MQTTUNSUBSCRIBE_H_ */
