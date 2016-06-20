
#pragma pack(1)
typedef struct tagPEER_INFO_DATA
{
	u_long inner_ip;		// 内网IP
	u_short inner_port;		// 内网端口
	u_short protocol_no;	// 协议号
	u_long net1_ip;			// NET1 IP
	u_short net1_port;		// NET1 端口
	u_long net2_ip;			// net2 IP
	u_short net2_port;		// net2 端口
	u_long unknown;
} PEER_INFO_DATA, *PPEER_INFO_DATA;
#pragma pack()


#pragma pack(1)
typedef struct tagPEER_LIST_RESP
{
	u_long checksum;		// 校验和
	u_char cmd_flag;		// 命令
	u_long seq;				// 序号
	u_char option_flag;		// 固定
	u_char unknown_fd;		// 未知
	u_char file_hash[16];	// file hash
	u_short peer_count;		// 请求的peer个数
} PEER_LIST_RESP, *PPEER_LIST_RESP;
#pragma pack()

/*
* 0x31回复
* 服务器返回PEER列表的相关信息
*/
