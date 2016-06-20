#include <stdio.h>
#include "winsock2.h"
#pragma comment(lib,"Ws2_32.lib")

#include <windows.h>
#include <cstdio>

#include "stdafx.h"
#include "mhook-lib/mhook.h"

#include "proto.h"
#include "crypt.h"

typedef struct _CLIENT_ID {
	DWORD_PTR UniqueProcess;
	DWORD_PTR UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef int (WINAPI* _sendto)		(SOCKET s,const char FAR * buf,int len,int flags,const struct sockaddr FAR * to,int tolen);
typedef int (WINAPI* _recvfrom)		(SOCKET s,char FAR * buf,int len,int flags,struct sockaddr FAR * from,int FAR * fromlen);

typedef int (WINAPI* _WSASend)		(SOCKET s,LPWSABUF lpBuffers,DWORD dwBufferCount,LPDWORD lpNumberOfBytesSent,DWORD dwFlags,LPWSAOVERLAPPED lpOverlapped,LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WINAPI* _WSARecv)		(SOCKET s,LPWSABUF lpBuffers,DWORD dwBufferCount,LPDWORD lpNumberOfBytesRecvd,LPDWORD lpFlags,LPWSAOVERLAPPED lpOverlapped,LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WINAPI* _WSASendTo)	(SOCKET s,LPWSABUF lpBuffers,DWORD dwBufferCount,LPDWORD lpNumberOfBytesSent,DWORD dwFlags,const struct sockaddr FAR * lpTo,int iTolen,LPWSAOVERLAPPED lpOverlapped,LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WINAPI* _WSARecvFrom)	(SOCKET s,LPWSABUF lpBuffers,DWORD dwBufferCount,LPDWORD lpNumberOfBytesRecvd,LPDWORD lpFlags,struct sockaddr FAR * lpFrom,LPINT lpFromlen,LPWSAOVERLAPPED lpOverlapped,LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

_sendto Truesendto		= (_sendto)GetProcAddress(GetModuleHandle(L"ws2_32"), "sendto");
_recvfrom Truerecvfrom	= (_recvfrom)GetProcAddress(GetModuleHandle(L"ws2_32"), "recvfrom");

_WSASend TrueWSASend			= (_WSASend)GetProcAddress(GetModuleHandle(L"ws2_32"), "WSASend");
_WSARecv TrueWSARecv			= (_WSARecv)GetProcAddress(GetModuleHandle(L"ws2_32"), "WSARecv");
_WSASendTo TrueWSASendTo		= (_WSASendTo)GetProcAddress(GetModuleHandle(L"ws2_32"), "WSASendTo");
_WSARecvFrom TrueWSARecvFrom	= (_WSARecvFrom)GetProcAddress(GetModuleHandle(L"ws2_32"), "WSARecvFrom");

int WINAPI Hooksendto(SOCKET s,const char FAR * buf,int len,int flags,const struct sockaddr FAR * to,int tolen)
{
	int nRetCode = 0;
	nRetCode = Truesendto(s,buf,len,flags,to,tolen);
	{	
		char lpHex[0x0E00] = {0};
		char lpLog[0x0F00] = {0};

		for (int i = 0; i < 0x20; i++)
		{
			sprintf(lpHex + 3*i,"%02X ",buf[i]);
		}
		sprintf_s(lpLog,sizeof(lpLog),"sendto->Buf:%08X|%s",len,lpHex);
		OutputDebugStringA(lpLog);
	}
	return nRetCode;
}
int WINAPI Hookrecvfrom(SOCKET s,char FAR * buf,int len,int flags,struct sockaddr FAR * from,int FAR * fromlen)
{
	int nRetCode = 0;
	nRetCode = Truerecvfrom(s,buf,len,flags,from,fromlen);
	{	
		char lpHex[0x0E00] = {0};
		char lpLog[0x0F00] = {0};

		for (int i = 0; i < 0x20; i++)
		{
			sprintf(lpHex + 3*i,"%02X ",buf[i]);
		}
		sprintf_s(lpLog,sizeof(lpLog),"recvfrom->Buf:%08X|%s",*(DWORD*)fromlen,lpHex);
		OutputDebugStringA(lpLog);
	}
	return nRetCode;
}


int	WINAPI	HookWSASend(SOCKET s,LPWSABUF lpBuffers,DWORD dwBufferCount,LPDWORD lpNumberOfBytesSent,DWORD dwFlags,LPWSAOVERLAPPED lpOverlapped,LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	int nRetCode = 0;

	nRetCode = TrueWSASend(s,lpBuffers,dwBufferCount,lpNumberOfBytesSent,dwFlags,lpOverlapped,lpCompletionRoutine);
	{	
		char lpHex[0x0E00] = {0};
		char lpLog[0x0F00] = {0};

		for (int i = 0; i < 0x20; i++)
		{
			sprintf(lpHex + 3*i,"%02X ",lpBuffers->buf[i]);
		}
		sprintf_s(lpLog,sizeof(lpLog),"WSASend->Buf:%s",lpHex);
		OutputDebugStringA(lpLog);
	}
	return nRetCode;
}

int	WINAPI	HookWSARecv(SOCKET s,LPWSABUF lpBuffers,DWORD dwBufferCount,LPDWORD lpNumberOfBytesRecvd,LPDWORD lpFlags,LPWSAOVERLAPPED lpOverlapped,LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	int nRetCode = 0;
	nRetCode = TrueWSARecv(s,lpBuffers,dwBufferCount,lpNumberOfBytesRecvd,lpFlags,lpOverlapped,lpCompletionRoutine);
	{
		char lpHex[0x0E00] = {0};
		char lpLog[0x0F00] = {0};

		for (int i = 0; i < 0x20; i++)
		{
			sprintf(lpHex + 3*i,"%02X ",lpBuffers->buf[i]);
		}
		sprintf_s(lpLog,sizeof(lpLog),"WSARecv->Buf:%s",lpHex);
		OutputDebugStringA(lpLog);
	}
	return nRetCode;
}
int	WINAPI	HookWSASendTo(SOCKET s,LPWSABUF lpBuffers,DWORD dwBufferCount,LPDWORD lpNumberOfBytesSent,DWORD dwFlags,const struct sockaddr FAR * lpTo,int iTolen,LPWSAOVERLAPPED lpOverlapped,LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	int nRetCode = 0;
	nRetCode = TrueWSASendTo(s,lpBuffers,dwBufferCount,lpNumberOfBytesSent,dwFlags,lpTo,iTolen,lpOverlapped,lpCompletionRoutine);
	if(*(BYTE*)(lpBuffers[0].buf+0x04) == 0x52)
	{	
		char lpLog[0x0F00] = {0};

		sprintf_s(lpLog,sizeof(lpLog),
			"WSASendTo->{IP:%-15s|port:%5d}dwBufferCount:%08X|BufLen:%08X|BytesRecved:%08X|nRetCode:%08X{VALID:%08X|CMD:%02X}",
			inet_ntoa(((sockaddr_in*)lpTo)->sin_addr),
			ntohs(((sockaddr_in*)lpTo)->sin_port),
			dwBufferCount,
			lpBuffers[0].len,
			*(DWORD*)lpNumberOfBytesSent,
			nRetCode,
			*(DWORD*)lpBuffers[0].buf,
			*(BYTE*)(lpBuffers[0].buf+0x04)
			);
		OutputDebugStringA(lpLog);		
	}
	return nRetCode;
}

int	WINAPI	HookWSARecvFrom(SOCKET s,LPWSABUF lpBuffers,DWORD dwBufferCount,LPDWORD lpNumberOfBytesRecvd,LPDWORD lpFlags,struct sockaddr FAR * lpFrom,LPINT lpFromlen,LPWSAOVERLAPPED lpOverlapped,LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	char buf[0x0600] = {0};

	int nRetCode = 0;
	nRetCode = TrueWSARecvFrom(s,lpBuffers,dwBufferCount,lpNumberOfBytesRecvd,lpFlags,lpFrom,lpFromlen,lpOverlapped,lpCompletionRoutine);
	if(*(BYTE*)(lpBuffers[0].buf+0x04) == 0x31)
	{	
		char lpLog[0x0F00] = {0};

		sprintf_s(lpLog,sizeof(lpLog),
			"WSARecvFrom->#begin#{IP:%-15s|port:%5d}dwBufferCount:%08X|BufLen:%08X|BytesRecved:%08X|nRetCode:%08X{VALID:%08X|CMD:%02X}",
			inet_ntoa(((sockaddr_in*)lpFrom)->sin_addr),
			ntohs(((sockaddr_in*)lpFrom)->sin_port),
			dwBufferCount,
			lpBuffers[0].len,
			*(DWORD*)lpNumberOfBytesRecvd,
			nRetCode,
			*(DWORD*)lpBuffers[0].buf,
			*(BYTE*)(lpBuffers[0].buf+0x04)
			);
		OutputDebugStringA(lpLog);		
	}
	
	if(*(BYTE*)(lpBuffers[0].buf+0x04) == 0x31)
	{
		PPEER_LIST_RESP p_peerlist_resp = (PPEER_LIST_RESP)(lpBuffers[0].buf);

		int resp_peer_count = p_peerlist_resp->peer_count;
		int head_len = sizeof(PEER_LIST_RESP);
		int pack_len = head_len + resp_peer_count*sizeof(PEER_INFO_DATA);

		memcpy_s(buf,head_len,lpBuffers[0].buf,head_len);

		for (int i=0; i < resp_peer_count; i++)
		{		
			PPEER_INFO_DATA ppeerlist_data = (PPEER_INFO_DATA)(buf + head_len + i*sizeof(PEER_INFO_DATA));
			ppeerlist_data->inner_ip = 0x64646464;
			ppeerlist_data->inner_port = 0x13B1+4*i;
			ppeerlist_data->protocol_no = 0x010C;
			ppeerlist_data->net1_ip = 0x64646464;
			ppeerlist_data->net1_port = 0x13B1+4*i;
			ppeerlist_data->net2_ip = 0x00000000;	
			ppeerlist_data->net2_port = 0x0000;
			ppeerlist_data->unknown = 0x0AFFFB03;
		}

		u_long check_sum = pack_checksum((u_char*)buf, pack_len);
		*(DWORD*)buf = check_sum;

		memcpy_s(lpBuffers[0].buf,lpBuffers[0].len,buf,lpBuffers[0].len);
		char hexlog[0x80] = {0};
		for (int i =0; (i < lpBuffers->len) && (i < 0x20); i++)
		{
			sprintf(hexlog+i*3,"%02X%c",(BYTE)buf[i],'-');
		}
		OutputDebugStringA(hexlog);

		memcpy_s(lpBuffers[1].buf,pack_len-lpBuffers[0].len,buf,pack_len-lpBuffers[0].len);
	}

// 	if(*(BYTE*)(lpBuffers[0].buf+0x04) == 0x31)
// 	{	
// 		char lpLog[0x0F00] = {0};
// 
// 		sprintf_s(lpLog,sizeof(lpLog),
// 			"WSARecvFrom->#end#{IP:%-15s|port:%5d}dwBufferCount:%08X|BufLen:%08X|BytesRecved:%08X|nRetCode:%08X{VALID:%08X|CMD:%02X}",
// 			inet_ntoa(((sockaddr_in*)lpFrom)->sin_addr),
// 			ntohs(((sockaddr_in*)lpFrom)->sin_port),
// 			dwBufferCount,
// 			lpBuffers[0].len,
// 			*(DWORD*)lpNumberOfBytesRecvd,
// 			nRetCode,
// 			*(DWORD*)lpBuffers[0].buf,
// 			*(BYTE*)(lpBuffers[0].buf+0x04)
// 			);
// 		OutputDebugStringA(lpLog);		
// 	}
// 
	return nRetCode;
}

INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved)
{
	HMODULE hPeerDll = NULL;
	switch(Reason)
	{
	case DLL_PROCESS_ATTACH:
		//Mhook_SetHook((PVOID*)&Truesendto, Hooksendto);
		//Mhook_SetHook((PVOID*)&Truerecvfrom, Hookrecvfrom);
		Mhook_SetHook((PVOID*)&TrueWSASendTo, HookWSASendTo);
		Mhook_SetHook((PVOID*)&TrueWSARecvFrom, HookWSARecvFrom);
		break;
	case DLL_PROCESS_DETACH:
		//Mhook_Unhook((PVOID*)&Truesendto);
		//Mhook_Unhook((PVOID*)&Truerecvfrom);
		Mhook_Unhook((PVOID*)&TrueWSASendTo);
		Mhook_Unhook((PVOID*)&TrueWSARecvFrom);
		OutputDebugString(L"[API HOOK]DLL_PROCESS_DETACH");

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	default:
		break;
	}
	return TRUE;
}