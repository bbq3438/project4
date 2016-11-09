/*
* netfilter.c
* (C) 2013, all rights reserved,
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
* DESCRIPTION:
* This is a simple traffic filter/firewall using WinDivert.
*
* usage: netfilter.exe windivert-filter [priority]
*
* Any traffic that matches the windivert-filter will be blocked using one of
* the following methods:
* - TCP: send a TCP RST to the packet's source.
* - UDP: send a ICMP(v6) "destination unreachable" to the packet's source.
* - ICMP/ICMPv6: Drop the packet.
*
* This program is similar to Linux's iptables with the "-j REJECT" target.
*/

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"

#define MAXBUF  0xFFFF
#define HTTP 80
#pragma warning(disable : 4200)


/*
* Entry.
*/
int main()
{
	HANDLE handle;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	unsigned char *payload;
	UINT packet_len;
	WINDIVERT_ADDRESS recv_addr;
	PWINDIVERT_IPHDR ipHeader;
	PWINDIVERT_TCPHDR tcpHeader;
	UINT payload_len;
	bool findString = false;
	char *pstr;


	// Divert traffic matching the filter:
	handle = WinDivertOpen("(tcp.DstPort == 80 or tcp.SrcPort == 80)", WINDIVERT_LAYER_NETWORK, priority, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	// Main loop:
	while (TRUE)
	{
		// Read a matching packet.
		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}

		findString = false;
		pstr = NULL;

		ipHeader = (PWINDIVERT_IPHDR)packet;
		tcpHeader = (PWINDIVERT_TCPHDR)(packet + 20);
		payload = (packet + 20 + tcpHeader->HdrLength * 4);

		if ((ipHeader == NULL) && (tcpHeader == NULL))
			continue;

		UINT8 *src_addr = (UINT8 *)&ipHeader->SrcAddr;
		UINT8 *dst_addr = (UINT8 *)&ipHeader->DstAddr;
		printf(" %u.%u.%u.%u -> %u.%u.%u.%u \n",
			src_addr[0], src_addr[1], src_addr[2], src_addr[3],
			dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
		printf("          %u -> %u\n\n",
			ntohs(tcpHeader->SrcPort), ntohs(tcpHeader->DstPort));

		// inbound
		// Michael -> GILBERT
		if (ntohs(tcpHeader->SrcPort) == HTTP)
		{
			if (pstr = strstr((char*)payload, "Michael"))
			{
				strncpy(pstr, "GILBERT", 7);
				findString = true;
			}
		}
		// outbound
		// gzip -> "    "
		else if (ntohs(tcpHeader->DstPort) == HTTP)
		{
			if (pstr = strstr((char*)payload, "gzip"))
			{
				strncpy(pstr, "    ", 4);
				findString = true;
			}		
		}

		// findString이 false 면 받은 패킷 그대로 전송
		// 하나라도 true 면 변조된 패킷 전송
		if (findString)
		{
			// checksum 계산
			WinDivertHelperCalcChecksums((PVOID)packet, packet_len, 0);
			// WinDivertSend
			if (!WinDivertSend(handle, packet, packet_len, &recv_addr, NULL))
			{
				printf("패킷 send 실패\n");
				continue;
			}
		}
		else
		{
			if (!WinDivertSend(handle, packet, packet_len, &recv_addr, NULL))
			{
				printf("패킷 send 실패\n");
				continue;
			}
		}
	}
}