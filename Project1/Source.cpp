#define _WINSOCK_DEPRECATED_NO_WARNINGS

#define DEFAULT_PACKET_SIZE 40
#define MAX_IP_PACKET_SIZE 65535

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <string.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

typedef struct icmp_packet
{
	BYTE	type;
	BYTE	code;
	USHORT	checksum;
	USHORT	id;
	USHORT	sequence;
} ICMP_PACKET, *PICMP_PAKET;



typedef struct ip_packet {
	BYTE ver_n_len;
	BYTE srv_type;
	USHORT total_len;
	USHORT pack_id;
	USHORT flags : 3;
	USHORT offset : 13;
	BYTE ttl;
	BYTE proto;
	USHORT checksum;
	UINT from_ip;
	UINT to_ip;
} IP_PACKET, *PIP_PACKET;



typedef struct packet_info {
	PSOCKADDR_IN from;
	DWORD ping;
} PACKET_INFO, *PPACKET_INFO;

USHORT calcCheckSum(USHORT *packet);

void print(PPACKET_INFO details, BOOL printIP);

int main(int argc, char *argv[])
{
	int iResult = 0;

	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 2);
	iResult = WSAStartup(wVersionRequested, &wsaData);
	if (iResult != NO_ERROR) {
		cout << "WSAStartup failed with erorr: " << WSAGetLastError() << endl;
		return 1;
	}

	PICMP_PAKET ICMPsendbuff = (PICMP_PAKET)malloc(DEFAULT_PACKET_SIZE);
	PIP_PACKET IPrecvbuff = (PIP_PACKET)malloc(MAX_IP_PACKET_SIZE);

	SOCKET socket = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, 0);
	if (socket == INVALID_SOCKET) {
		cout << "WSASocket failed with error: " << WSAGetLastError() << endl;
		iResult = WSACleanup();
		if (iResult != NO_ERROR) {
			cout << "WSACleanup failed with error: " << WSAGetLastError() << endl;
		}
		return 1;
	}


	SOCKADDR_IN source;
	SOCKADDR_IN destination;

	UINT toAddr = inet_addr(argv[1]);
	destination.sin_addr.s_addr = toAddr;
	destination.sin_family = AF_INET;

	PACKET_INFO details;
	int number = 1;
	byte seq = 1;
	BOOL traceEnd = FALSE, error = FALSE, printIP;
	int hops = 30;
	int ttl = 0;

	cout << "Traceroute to " << argv[1] << endl;
	cout << "with hops equal to 30:" << endl;

	do
	{
		ttl++;

		iResult = setsockopt(socket, IPPROTO_IP, IP_TTL, (char *)&ttl, sizeof(int));
		if (iResult == SOCKET_ERROR) {
			cout << "setsockopt failed with error: " << WSAGetLastError() << endl;
			iResult = WSACleanup();
			if (iResult == SOCKET_ERROR) {
				cout << "WSACleanup failed with error: " << WSAGetLastError() << endl;
			}
			return 1;
		}

		printIP = FALSE;
		printf("%3d.", number++);

		for (int i = 1; i <= 3; i++) {
			if (i == 3) {
				printIP = TRUE;
			}

			// Initialize the ICMP packet
			ICMPsendbuff->type = 8;
			ICMPsendbuff->code = 0;
			ICMPsendbuff->id = 1;
			ICMPsendbuff->sequence = seq;
			ICMPsendbuff->checksum = 0;
			ICMPsendbuff->checksum = calcCheckSum((USHORT *)ICMPsendbuff);

			//---------------------------------------------
			// Ping

			static ULONG startPingTime, endPingTime;
			startPingTime = GetTickCount();

			iResult = sendto(socket, (char *)ICMPsendbuff, DEFAULT_PACKET_SIZE, 0, (PSOCKADDR)&destination, sizeof(SOCKADDR_IN));
			if (iResult == SOCKET_ERROR) {
				cout << "sendto failed with error: " << WSAGetLastError() << endl;
				iResult = WSACleanup();
				if (iResult == SOCKET_ERROR) {
					cout << "WSACleanup failed with error: " << WSAGetLastError() << endl;
				}
				return 1;
			}

			static fd_set socketToCheck;
			socketToCheck.fd_count = 1;
			socketToCheck.fd_array[0] = socket;

			static TIMEVAL timeToWait;
			timeToWait.tv_sec = 2;
			timeToWait.tv_usec = 0;

			iResult = select(0, &socketToCheck, NULL, NULL, &timeToWait);
			if (iResult == SOCKET_ERROR) {
				cout << "select failed with error: " << WSAGetLastError() << endl;
				iResult = WSACleanup();
				if (iResult == SOCKET_ERROR) {
					cout << "WSACleanup failed with error: " << WSAGetLastError() << endl;
				}
				return 1;
			}

			static int recvResult;
			recvResult = iResult;
			if (recvResult != 0) {
				static int sockaddr_inLength = sizeof(SOCKADDR_IN);
				recvResult = recvfrom(socket, (char *)IPrecvbuff, 1024, 0, (PSOCKADDR)&source, &sockaddr_inLength);
				if (recvResult == SOCKET_ERROR) {
					cout << "select failed with error: " << WSAGetLastError() << endl;
					iResult = WSACleanup();
					if (iResult == SOCKET_ERROR) {
						cout << "WSACleanup failed with error: " << WSAGetLastError() << endl;
					}
					return 1;
				}
			}


			endPingTime = GetTickCount();

			// end Ping
			//---------------------------------------------

			static int decodeRes;
			if (recvResult == 0) {
				cout << "     *";
			}
			else {
				USHORT IPpacket_headerLength = (IPrecvbuff->ver_n_len & 0x0F) * 4;
				PICMP_PAKET ICMPpacket_header = (PICMP_PAKET)((char *)IPrecvbuff + IPpacket_headerLength);

				decodeRes = -1; // error
				switch (ICMPpacket_header->type) {
				case 0:
					if (ICMPpacket_header->sequence == seq) {
						details.from = &source;
						details.ping = endPingTime - startPingTime;
						decodeRes = 1; // last hop
					}
					break;
				case 11:
					PIP_PACKET requestIPpacket_header = (PIP_PACKET)((char *)ICMPpacket_header + 8);
					USHORT requestIPpaket_headerLength = (requestIPpacket_header->ver_n_len & 0x0F) * 4;

					PICMP_PAKET requestICMPheader = (PICMP_PAKET)((char *)requestIPpacket_header + requestIPpaket_headerLength);

					if (requestICMPheader->sequence == seq) {
						details.from = &source;
						details.ping = endPingTime - startPingTime;
						decodeRes = 2; //ttl = 0
					}
					break;
				}
			}


			if (recvResult > 1) {
				switch (decodeRes) {
				case -1:
					cout << "  *";
					break;
				case 1:
					traceEnd = TRUE;
				case 2:
					print(&details, printIP);
					break;
				}
			}
		}
		cout << endl;
	} while (!traceEnd && (ttl != hops));
	system("pause");
}




USHORT calcCheckSum(USHORT *packet) {
	ULONG checksum = 0;
	int size = 40;
	while (size > 1) {
		checksum += *(packet++);
		size -= sizeof(USHORT);
	}
	if (size) checksum += *(UCHAR *)packet;

	checksum = (checksum >> 16) + (checksum & 0xFFFF);
	checksum += (checksum >> 16);

	return (USHORT)(~checksum);
}


void print(PPACKET_INFO details, BOOL printIP)
{
	printf("%6d", details->ping);

	if (printIP) {
		char *srcAddr = inet_ntoa(details->from->sin_addr);
		if (srcAddr != NULL) {
			printf("\t%s", srcAddr);
		}
		char hbuf[NI_MAXHOST];
		if (!getnameinfo((struct sockaddr *)(details->from), sizeof(struct sockaddr_in), hbuf, sizeof(hbuf),
			NULL, 0, NI_NAMEREQD))
			printf(" %s", hbuf);
	}
}