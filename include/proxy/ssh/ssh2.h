/*
 * ProFTPD - mod_proxy SSH2 constants
 * Copyright (c) 2021 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#ifndef MOD_PROXY_SSH_SSH2_H
#define MOD_PROXY_SSH_SSH2_H

/* As per RFC 4253, Section 6.1, we MUST be able to handle a packet whose
 * length is 35000 bytes; we SHOULD be able to handle larger packets.  We
 * impose a maximum size here to prevent overly-large packets from being
 * used by attackers.  The maximum size is a bit arbitrary.
 */
#define PROXY_SSH_MAX_PACKET_LEN		(1024 * 256)

/* SSH2 message types */

#define PROXY_SSH_MSG_DISCONNECT		1
#define PROXY_SSH_MSG_IGNORE			2
#define PROXY_SSH_MSG_UNIMPLEMENTED		3
#define PROXY_SSH_MSG_DEBUG			4
#define PROXY_SSH_MSG_SERVICE_REQUEST		5
#define PROXY_SSH_MSG_SERVICE_ACCEPT		6
#define PROXY_SSH_MSG_EXT_INFO			7
#define PROXY_SSH_MSG_KEXINIT			20
#define PROXY_SSH_MSG_NEWKEYS			21

/* Key exchange message types */
#define PROXY_SSH_MSG_KEX_DH_INIT		30
#define PROXY_SSH_MSG_KEX_DH_REPLY		31
#define PROXY_SSH_MSG_KEX_DH_GEX_REQUEST_OLD	30
#define PROXY_SSH_MSG_KEX_DH_GEX_GROUP		31
#define PROXY_SSH_MSG_KEX_DH_GEX_INIT		32
#define PROXY_SSH_MSG_KEX_DH_GEX_REPLY		33
#define PROXY_SSH_MSG_KEX_DH_GEX_REQUEST	34
#define PROXY_SSH_MSG_KEXRSA_PUBKEY		30
#define PROXY_SSH_MSG_KEXRSA_SECRET		31
#define PROXY_SSH_MSG_KEXRSA_DONE		32
#define PROXY_SSH_MSG_KEX_ECDH_INIT		30
#define PROXY_SSH_MSG_KEX_ECDH_REPLY		31

/* User authentication message types */
#define PROXY_SSH_MSG_USER_AUTH_REQUEST		50
#define PROXY_SSH_MSG_USER_AUTH_FAILURE		51
#define PROXY_SSH_MSG_USER_AUTH_SUCCESS		52
#define PROXY_SSH_MSG_USER_AUTH_BANNER		53
#define PROXY_SSH_MSG_USER_AUTH_PUBKEY		60
#define PROXY_SSH_MSG_USER_AUTH_PK_OK		60
#define PROXY_SSH_MSG_USER_AUTH_PASSWD		60
#define PROXY_SSH_MSG_USER_AUTH_INFO_REQ	60
#define PROXY_SSH_MSG_USER_AUTH_INFO_RESP	61

/* Request types */
#define PROXY_SSH_MSG_GLOBAL_REQUEST		80
#define PROXY_SSH_MSG_REQUEST_SUCCESS		81
#define PROXY_SSH_MSG_REQUEST_FAILURE		82

/* Channel message types */
#define PROXY_SSH_MSG_CHANNEL_OPEN 		90
#define PROXY_SSH_MSG_CHANNEL_OPEN_CONFIRMATION	91
#define PROXY_SSH_MSG_CHANNEL_OPEN_FAILURE	92
#define PROXY_SSH_MSG_CHANNEL_WINDOW_ADJUST	93
#define PROXY_SSH_MSG_CHANNEL_DATA		94
#define PROXY_SSH_MSG_CHANNEL_EXTENDED_DATA	95
#define PROXY_SSH_MSG_CHANNEL_EOF		96
#define PROXY_SSH_MSG_CHANNEL_CLOSE		97
#define PROXY_SSH_MSG_CHANNEL_REQUEST		98
#define PROXY_SSH_MSG_CHANNEL_SUCCESS		99
#define PROXY_SSH_MSG_CHANNEL_FAILURE		100

/* Channel extended data types */
#define PROXY_SSH_MSG_CHANNEL_EXTENDED_DATA_TYPE_STDERR		1

/* SSH Disconnect reason codes */
#define PROXY_SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT	1
#define PROXY_SSH_DISCONNECT_PROTOCOL_ERROR			2
#define PROXY_SSH_DISCONNECT_KEY_EXCHANGE_FAILED		3
#define PROXY_SSH_DISCONNECT_RESERVED				4
#define PROXY_SSH_DISCONNECT_MAC_ERROR				5
#define PROXY_SSH_DISCONNECT_COMPRESSION_ERROR			6
#define PROXY_SSH_DISCONNECT_SERVICE_NOT_AVAILABLE		7
#define PROXY_SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED	8
#define PROXY_SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE		9
#define PROXY_SSH_DISCONNECT_CONNECTION_LOST			10
#define PROXY_SSH_DISCONNECT_BY_APPLICATION			11
#define PROXY_SSH_DISCONNECT_TOO_MANY_CONNECTIONS		12
#define PROXY_SSH_DISCONNECT_AUTH_CANCELLED_BY_USER		13
#define PROXY_SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE	14
#define PROXY_SSH_DISCONNECT_ILLEGAL_USER_NAME			15

#define PROXY_SSH_ID_PREFIX          "SSH-2.0-"
#define PROXY_SSH_ID_DEFAULT_STRING  PROXY_SSH_ID_PREFIX MOD_PROXY_VERSION

#endif /* MOD_PROXY_SSH_SSH2_H */
