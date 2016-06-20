
u_long pack_checksum(u_char *pktbuf, int pktlen)
{
	pktlen -= 4;
	if ( pktlen <= 0 )
		return 0;
	pktbuf += 4;

	u_long key; // ebx@1
	DWORD v3; // eax@6
	LPBYTE v4; // esi@6
	DWORD v5; // edx@6
	unsigned int v14; // [sp+3Ch] [bp-Ch]@5
	unsigned int v15; // [sp+40h] [bp-8h]@1
	unsigned char v16; // [sp+47h] [bp-1h]@1

	key = 0x10312312;
	v15 = 0x10312312;
	v16 = 0;

	do
	{
		--pktlen;
		v16 = pktbuf[pktlen];

		if ( pktlen >= 8 )
		{
			v14 = pktlen >> 3;
			do
			{
				v3 = *(DWORD *)pktbuf;
				v4 = pktbuf + 4;
				v5 = v3 ^ *(DWORD *)v4 ^ (key >> 6) ^ (key << 14);
				key = v5 ^ v15;
				pktbuf = v4 + 4;
				pktlen -= 8;
				v15 ^= v5;
			} while ( --v14 > 0 );
		}
	} while ( pktlen - 8 >= 0 );

	while ( pktlen-- )
	{
		key ^= *pktbuf++ ^ (key << 7) ^ (key >> 13);
	}

	return key ^ v16 ^ (key << 7) ^ (key >> 13);
}