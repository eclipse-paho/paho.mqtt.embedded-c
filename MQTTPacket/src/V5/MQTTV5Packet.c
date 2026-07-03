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

#include <string.h>

/**
 * Writes an integer as 4 bytes to an output buffer.
 * @param pptr pointer to the output buffer - incremented by the number of bytes used & returned
 * @param anInt the integer to write
 */
void writeInt4(unsigned char** pptr, int anInt)
{
  **pptr = (unsigned char)(anInt / 16777216);
  (*pptr)++;
  anInt %= 16777216;
  **pptr = (unsigned char)(anInt / 65536);
  (*pptr)++;
  anInt %= 65536;
	**pptr = (unsigned char)(anInt / 256);
	(*pptr)++;
	**pptr = (unsigned char)(anInt % 256);
	(*pptr)++;
}


/**
 * Calculates an integer from 4 bytes read from the input buffer
 * @param pptr pointer to the input buffer - incremented by the number of bytes used & returned
 * @return the integer value calculated
 */
int readInt4(unsigned char** pptr)
{
	unsigned char* ptr = *pptr;
	int value = 16777216*(*ptr) + 65536*(*(ptr+1)) + 256*(*(ptr+2)) + (*(ptr+3));
	*pptr += 4;
	return value;
}


void writeMQTTLenString(unsigned char** pptr, MQTTLenString lenstring)
{
  writeInt(pptr, lenstring.len);
  memcpy(*pptr, lenstring.data, lenstring.len);
  *pptr += lenstring.len;
}


int MQTTLenStringRead(MQTTLenString* lenstring, unsigned char** pptr, unsigned char* enddata)
{
	int len = 0;

	/* the first two bytes are the length of the string */
	if (enddata - (*pptr) > 1) /* enough length to read the integer? */
	{
		lenstring->len = readInt(pptr); /* increments pptr to point past length */
		if (&(*pptr)[lenstring->len] <= enddata)
		{
			lenstring->data = (char*)*pptr;
			*pptr += lenstring->len;
			len = 2 + lenstring->len;
		}
	}
	return len;
}
