/*******************************************************************************
 * Copyright (c) 2023, 2026 Microsoft Corporation, Ian Craggs. All rights reserved.
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
 *******************************************************************************/

#include "V5/MQTTV5Packet.h"

static const char* v5property_identifier_to_string(int identifier)
{
    switch (identifier) 
    {
        case MQTTPROPERTY_CODE_PAYLOAD_FORMAT_INDICATOR:
            return "MQTTPROPERTY_CODE_PAYLOAD_FORMAT_INDICATOR";
        case MQTTPROPERTY_CODE_MESSAGE_EXPIRY_INTERVAL:
            return "MQTTPROPERTY_CODE_MESSAGE_EXPIRY_INTERVAL";
        case MQTTPROPERTY_CODE_CONTENT_TYPE:
            return "MQTTPROPERTY_CODE_CONTENT_TYPE";
        case MQTTPROPERTY_CODE_RESPONSE_TOPIC:
            return "MQTTPROPERTY_CODE_RESPONSE_TOPIC";
        case MQTTPROPERTY_CODE_CORRELATION_DATA:
                return "MQTTPROPERTY_CODE_CORRELATION_DATA";
        case MQTTPROPERTY_CODE_SUBSCRIPTION_IDENTIFIER:
                return "MQTTPROPERTY_CODE_SUBSCRIPTION_IDENTIFIER";
        case MQTTPROPERTY_CODE_SESSION_EXPIRY_INTERVAL:
                return "MQTTPROPERTY_CODE_SESSION_EXPIRY_INTERVAL";
        case MQTTPROPERTY_CODE_ASSIGNED_CLIENT_IDENTIFER:
                return "MQTTPROPERTY_CODE_ASSIGNED_CLIENT_IDENTIFER";
        case MQTTPROPERTY_CODE_SERVER_KEEP_ALIVE:
                return "MQTTPROPERTY_CODE_SERVER_KEEP_ALIVE";
        case MQTTPROPERTY_CODE_AUTHENTICATION_METHOD:
                return "MQTTPROPERTY_CODE_AUTHENTICATION_METHOD";
        case MQTTPROPERTY_CODE_AUTHENTICATION_DATA:
                return "MQTTPROPERTY_CODE_AUTHENTICATION_DATA";
        case MQTTPROPERTY_CODE_REQUEST_PROBLEM_INFORMATION:
                return "MQTTPROPERTY_CODE_REQUEST_PROBLEM_INFORMATION";
        case MQTTPROPERTY_CODE_WILL_DELAY_INTERVAL:
                return "MQTTPROPERTY_CODE_WILL_DELAY_INTERVAL";
        case MQTTPROPERTY_CODE_REQUEST_RESPONSE_INFORMATION:
                return "MQTTPROPERTY_CODE_REQUEST_RESPONSE_INFORMATION";
        case MQTTPROPERTY_CODE_RESPONSE_INFORMATION:
                return "MQTTPROPERTY_CODE_RESPONSE_INFORMATION";
        case MQTTPROPERTY_CODE_SERVER_REFERENCE:
                return "MQTTPROPERTY_CODE_SERVER_REFERENCE";
        case MQTTPROPERTY_CODE_REASON_STRING:
                return "MQTTPROPERTY_CODE_REASON_STRING";
        case MQTTPROPERTY_CODE_RECEIVE_MAXIMUM:
                return "MQTTPROPERTY_CODE_RECEIVE_MAXIMUM";
        case MQTTPROPERTY_CODE_TOPIC_ALIAS_MAXIMUM:
                return "MQTTPROPERTY_CODE_TOPIC_ALIAS_MAXIMUM";
        case MQTTPROPERTY_CODE_TOPIC_ALIAS:
                return "MQTTPROPERTY_CODE_TOPIC_ALIAS";
        case MQTTPROPERTY_CODE_MAXIMUM_QOS:
                return "MQTTPROPERTY_CODE_MAXIMUM_QOS";
        case MQTTPROPERTY_CODE_RETAIN_AVAILABLE:
                return "MQTTPROPERTY_CODE_RETAIN_AVAILABLE";
        case MQTTPROPERTY_CODE_USER_PROPERTY:
                return "MQTTPROPERTY_CODE_USER_PROPERTY";
        case MQTTPROPERTY_CODE_MAXIMUM_PACKET_SIZE:
                return "MQTTPROPERTY_CODE_MAXIMUM_PACKET_SIZE";
        case MQTTPROPERTY_CODE_WILDCARD_SUBSCRIPTION_AVAILABLE:
                return "MQTTPROPERTY_CODE_WILDCARD_SUBSCRIPTION_AVAILABLE";
        case MQTTPROPERTY_CODE_SUBSCRIPTION_IDENTIFIER_AVAILABLE:
                return "MQTTPROPERTY_CODE_SUBSCRIPTION_IDENTIFIER_AVAILABLE";
        case MQTTPROPERTY_CODE_SHARED_SUBSCRIPTION_AVAILABLE:
                return "MQTTPROPERTY_CODE_SHARED_SUBSCRIPTION_AVAILABLE";
        default:
            return "MQTTPROPERTY_CODE_UNKNOWN";
    }
}

static const char* v5property_type_to_string(int type)
{
    switch (type)
    {
        case MQTTPROPERTY_TYPE_BYTE:
            return "MQTTPROPERTY_TYPE_BYTE";
        case MQTTPROPERTY_TYPE_TWO_BYTE_INTEGER:
            return "MQTTPROPERTY_TYPE_TWO_BYTE_INTEGER";
        case MQTTPROPERTY_TYPE_FOUR_BYTE_INTEGER:
            return "MQTTPROPERTY_TYPE_FOUR_BYTE_INTEGER";
        case MQTTPROPERTY_TYPE_VARIABLE_BYTE_INTEGER:
            return "MQTTPROPERTY_TYPE_VARIABLE_BYTE_INTEGER";
        case MQTTPROPERTY_TYPE_BINARY_DATA:
            return "MQTTPROPERTY_TYPE_BINARY_DATA";
        case MQTTPROPERTY_TYPE_UTF_8_ENCODED_STRING:
            return "MQTTPROPERTY_TYPE_UTF_8_ENCODED_STRING";
        case MQTTPROPERTY_TYPE_UTF_8_STRING_PAIR:
            return "MQTTPROPERTY_TYPE_UTF_8_STRING_PAIR";
        default:
            return "MQTTPROPERTY_TYPE_UNKNOWN";
    }
}

void v5property_print(MQTTProperty property)
{
    const char* identifier_str = v5property_identifier_to_string(property.identifier);
    int type = MQTTProperty_getType(property.identifier);
    const char* type_str = v5property_type_to_string(type);

    switch(type)
    {
        case MQTTPROPERTY_TYPE_BYTE:
            printf("\t%s (%s) = %d\n", identifier_str, type_str, (int)property.value.byte);
            break;
        case MQTTPROPERTY_TYPE_TWO_BYTE_INTEGER:
            printf("\t%s (%s) = %d\n", identifier_str, type_str, (int)property.value.integer2);
            break;
        case MQTTPROPERTY_TYPE_FOUR_BYTE_INTEGER:
            printf("\t%s (%s) = %d\n", identifier_str, type_str, (int)property.value.integer4);
            break;
        case MQTTPROPERTY_TYPE_VARIABLE_BYTE_INTEGER:
            printf("\t%s (%s) = %d\n", identifier_str, type_str, (int)property.value.integer4);
            break;
        case MQTTPROPERTY_TYPE_BINARY_DATA:
            printf("\t%s (%s) = [%.*s]\n", identifier_str, type_str, 
                property.value.data.len, property.value.data.data);
            break;
        case MQTTPROPERTY_TYPE_UTF_8_ENCODED_STRING:
            printf("\t%s (%s) = [%.*s]\n", identifier_str, type_str, 
                property.value.data.len, property.value.data.data);
            break;
        case MQTTPROPERTY_TYPE_UTF_8_STRING_PAIR:
            printf("\t%s: (%s) = [%.*s], [%.*s]\n", identifier_str, type_str, 
                property.value.string_pair.key.len, property.value.string_pair.key.data,
                property.value.string_pair.val.len, property.value.string_pair.val.data);
            break;
        default:
            printf("\tUNKNOWN Property\n");
    }
}

const char* v5reasoncode_to_string(enum MQTTReasonCodes reasoncode)
{
    switch (reasoncode)
    {
        case MQTTREASONCODE_SUCCESS:
            return "MQTTREASONCODE_SUCCESS";
        case MQTTREASONCODE_NO_MATCHING_SUBSCRIBERS:
            return "MQTTREASONCODE_NO_MATCHING_SUBSCRIBERS";
        case MQTTREASONCODE_NO_SUBSCRIPTION_FOUND:
            return "MQTTREASONCODE_NO_SUBSCRIPTION_FOUND";
        case MQTTREASONCODE_CONTINUE_AUTHENTICATION:
            return "MQTTREASONCODE_CONTINUE_AUTHENTICATION";
        case MQTTREASONCODE_RE_AUTHENTICATE:
            return "MQTTREASONCODE_RE_AUTHENTICATE";
        case MQTTREASONCODE_UNSPECIFIED_ERROR:
            return "MQTTREASONCODE_UNSPECIFIED_ERROR";
        case MQTTREASONCODE_MALFORMED_PACKET:
            return "MQTTREASONCODE_MALFORMED_PACKET";
        case MQTTREASONCODE_PROTOCOL_ERROR:
            return "MQTTREASONCODE_PROTOCOL_ERROR";
        case MQTTREASONCODE_IMPLEMENTATION_SPECIFIC_ERROR:
            return "MQTTREASONCODE_IMPLEMENTATION_SPECIFIC_ERROR";
        case MQTTREASONCODE_UNSUPPORTED_PROTOCOL_VERSION:
            return "MQTTREASONCODE_UNSUPPORTED_PROTOCOL_VERSION";
        case MQTTREASONCODE_CLIENT_IDENTIFIER_NOT_VALID:
            return "MQTTREASONCODE_CLIENT_IDENTIFIER_NOT_VALID";
        case MQTTREASONCODE_BAD_USER_NAME_OR_PASSWORD:
            return "MQTTREASONCODE_BAD_USER_NAME_OR_PASSWORD";
        case MQTTREASONCODE_NOT_AUTHORIZED:
            return "MQTTREASONCODE_NOT_AUTHORIZED";
        case MQTTREASONCODE_SERVER_UNAVAILABLE:
            return "MQTTREASONCODE_SERVER_UNAVAILABLE";
        case MQTTREASONCODE_SERVER_BUSY:
            return "MQTTREASONCODE_SERVER_BUSY";
        case MQTTREASONCODE_BANNED:
            return "MQTTREASONCODE_BANNED";
        case MQTTREASONCODE_SERVER_SHUTTING_DOWN:
            return "MQTTREASONCODE_SERVER_SHUTTING_DOWN";
        case MQTTREASONCODE_BAD_AUTHENTICATION_METHOD:
            return "MQTTREASONCODE_BAD_AUTHENTICATION_METHOD";
        case MQTTREASONCODE_KEEP_ALIVE_TIMEOUT:
            return "MQTTREASONCODE_KEEP_ALIVE_TIMEOUT";
        case MQTTREASONCODE_SESSION_TAKEN_OVER:
            return "MQTTREASONCODE_SESSION_TAKEN_OVER";
        case MQTTREASONCODE_TOPIC_FILTER_INVALID:
            return "MQTTREASONCODE_TOPIC_FILTER_INVALID";
        case MQTTREASONCODE_TOPIC_NAME_INVALID:
            return "MQTTREASONCODE_TOPIC_NAME_INVALID";
        case MQTTREASONCODE_PACKET_IDENTIFIER_IN_USE:
            return "MQTTREASONCODE_PACKET_IDENTIFIER_IN_USE";
        case MQTTREASONCODE_PACKET_IDENTIFIER_NOT_FOUND:
            return "MQTTREASONCODE_PACKET_IDENTIFIER_NOT_FOUND";
        case MQTTREASONCODE_RECEIVE_MAXIMUM_EXCEEDED:
            return "MQTTREASONCODE_RECEIVE_MAXIMUM_EXCEEDED";
        case MQTTREASONCODE_TOPIC_ALIAS_INVALID:
            return "MQTTREASONCODE_TOPIC_ALIAS_INVALID";
        case MQTTREASONCODE_PACKET_TOO_LARGE:
            return "MQTTREASONCODE_PACKET_TOO_LARGE";
        case MQTTREASONCODE_MESSAGE_RATE_TOO_HIGH:
            return "MQTTREASONCODE_MESSAGE_RATE_TOO_HIGH";
        case MQTTREASONCODE_QUOTA_EXCEEDED:
            return "MQTTREASONCODE_QUOTA_EXCEEDED";
        case MQTTREASONCODE_ADMINISTRATIVE_ACTION:
            return "MQTTREASONCODE_ADMINISTRATIVE_ACTION";
        case MQTTREASONCODE_PAYLOAD_FORMAT_INVALID:
            return "MQTTREASONCODE_PAYLOAD_FORMAT_INVALID";
        case MQTTREASONCODE_RETAIN_NOT_SUPPORTED:
            return "MQTTREASONCODE_RETAIN_NOT_SUPPORTED";
        case MQTTREASONCODE_QOS_NOT_SUPPORTED:
            return "MQTTREASONCODE_QOS_NOT_SUPPORTED";
        case MQTTREASONCODE_USE_ANOTHER_SERVER:
            return "MQTTREASONCODE_USE_ANOTHER_SERVER";
        case MQTTREASONCODE_SERVER_MOVED:
            return "MQTTREASONCODE_SERVER_MOVED";
        case MQTTREASONCODE_SHARED_SUBSCRIPTION_NOT_SUPPORTED:
            return "MQTTREASONCODE_SHARED_SUBSCRIPTION_NOT_SUPPORTED";
        case MQTTREASONCODE_CONNECTION_RATE_EXCEEDED:
            return "MQTTREASONCODE_CONNECTION_RATE_EXCEEDED";
        case MQTTREASONCODE_MAXIMUM_CONNECT_TIME:
            return "MQTTREASONCODE_MAXIMUM_CONNECT_TIME";
        case MQTTREASONCODE_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED:
            return "MQTTREASONCODE_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED";
        case MQTTREASONCODE_WILDCARD_SUBSCRIPTION_NOT_SUPPORTED:
            return "MQTTREASONCODE_WILDCARD_SUBSCRIPTION_NOT_SUPPORTED";
        default:
            return "MQTTREASONCODE_UNKNOWN";
    }
}
