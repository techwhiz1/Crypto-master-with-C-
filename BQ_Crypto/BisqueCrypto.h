#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <zlib.h>

#undef LOBYTE
#include "defs.h"

struct V128 {
	uint64 m_Data[2];

	void operator=(V128 in) {
		m_Data[0] = in.m_Data[0];
		m_Data[1] = in.m_Data[1];
	};
};


// RBase64
std::vector<uint8> RB64Decode(const char* data);
std::string RB64Encode(const uint8* buf, uint32 bufLen);

static uint32 bswap32(uint32 x) {
	return ((x << 24) & 0xff000000) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00) | ((x >> 24) & 0x000000ff);
}

/*
	Rapide anaylse de l'algorithme et du mode de chiffrement :

	1/ L'algorithme g�n�re tout d'abord un contexte de cl� de plusieurs KB avec diverses
		op�rations de m�langes (globalement bas�s sur des donn�es statiques).

	2/ Les donn�es sont segment�s en blocs de 16 octets, chacun de ces bloc
		subit des permutations qui sont statiquement d�fini dans le code et facilement
		identifiable.

	3/ Les donn�es subissent ensuite un traitements � plusieurs tours de chiffrement sur le
		meme bloc (il d�pend exclusivement de la taille de la cl� utilis�).
		Pour la cl� initiale de 24 octets, le nombre de tours est de 12.
		Chaque tour de chiffrement effectue une multitude d'op�rations de substitutions avec
		plusieurs tables de substitutions statiques.
		Les donn�es subissent une multitudes d'op�rations de m�langes complexes, de XOR et
		de rotations au niveau des bits.

	Il est � not� qu'� chaque �tape du chiffrement se trouve des sous-fonctions de m�langes bas�
	sur la "crypto-table" (d'environ 8 KB). Alors bien que beaucoup de tables statiques soient
	utilis�s, le m�lange des donn�es contre-balance cela.


	
	Pour le jeu :

	Etonnement la s�curit� reste relativement m�diocre puisque ce chiffrement n'utilise
	pas de mode �volutif, il reste simplement en mode d'op�ration ECB ce qui laisse
	la possibilit� de r�aliser une cryptanalyses fr�quentielle sur les blocs.
	La cl� initiale n'est pas vraiment cach� non plus.
*/
class MD159
{
public:
	struct KeyContext
	{
		uint8 m_Data[40];

		void* m_Alloc0 = 0;
		void* m_Alloc1 = 0;
		void* m_Alloc2 = 0;

		~KeyContext()
		{
			if (m_Alloc0) {
				free(m_Alloc0);
				m_Alloc0 = 0;
			}
			if (m_Alloc1) {
				free(m_Alloc1);
				m_Alloc1 = 0;
			}
			if (m_Alloc2) {
				free(m_Alloc2);
				m_Alloc2 = 0;
			}
		}
	};

private:
	KeyContext m_KeyContext;

public:
	int64 InitializeKey(const char* pKey, uint32 keyLen);
	int Decrypt(const uint8* data, uint32 size, std::vector<uint8>& decrypted);
	int Encrypt(const uint8* data, uint32 size, std::vector<uint8>& encrypted);

	int DecryptMD144(const uint8* data, uint32 size, std::vector<uint8>& decrypted);
	int DecryptMD40S(const uint8* data, uint32 size, std::vector<uint8>& decrypted);
};
