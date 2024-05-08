#include "BisqueCrypto.h"

#include <vector>
#include <string>
typedef unsigned char uint8;


#pragma region(LOG_PART)
bool inline IsASCII(const uint8 byte) { return (byte >= 33 && byte <= 126); }

void PrintHexLine(const uint8* data, int sz)
{
    const int perLine = 16;
    int lines = (sz / perLine) + (((sz % perLine) > 0) ? 1 : 0);

    printf("\n");
    for (int i = 0; i < lines; i++)
    {
        int restInLine = (sz - (i * perLine));
        if (restInLine > perLine)
            restInLine = perLine;

        for (int x = 0; x < restInLine; x++) {
            int it = (i * perLine) + x;
            printf("%02hhX ", data[it]);
        }

        printf("   ");
        for (int x = 0; x < restInLine; x++) {
            int it = (i * perLine) + x;
            printf("%c", IsASCII(data[it]) ? data[it] : '.');
        }

        printf("\n");
    }
    printf("\n");
}
#pragma endregion


int main()
{
    // NTY decrypt bedtest
    {
        HANDLE hFile = CreateFileA(
            // "C:\\Users\\Unknown8192\\Desktop\\Freelance_Jobs\\scenario_001_01_020.txt.nty",
            // "C:\\Users\\Unknown8192\\Desktop\\Freelance_Jobs\\SakuraMasterDb01-254.nty",
            "C:\\Users\\Unknown8192\\Desktop\\Freelance_Jobs\\scenario_event_001_01_020_anim.ssd.nty",
            // "C:\\Users\\Unknown8192\\Desktop\\Freelance_Jobs\\app_banner_superevolve_0808_kbEIgNe4Ps.png.nty",
            GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
        DWORD reads = 0;
        LARGE_INTEGER fSize = {};
        GetFileSizeEx(hFile, &fSize);
        uint8* dataFile = new uint8[fSize.QuadPart + 64];
        ReadFile(hFile, dataFile, fSize.QuadPart, &reads, 0);
        CloseHandle(hFile);

        // if (*(uint32*)dataFile == 0x2A004D4D)
        {
            uint32 fileDataBlockSz = bswap32(*(uint32*)(dataFile + 4));

            const char* KeyToUse = "J6oxF6iN";

            MD159 ctx = {};
            ctx.InitializeKey(KeyToUse, strlen(KeyToUse));

            std::vector<uint8> decrypted;
            ctx.DecryptMD144(dataFile + 16, fileDataBlockSz, decrypted);
            // decrypted.insert(decrypted.begin(), dataFile + 16, fileDataBlockSz);
            uint8* pDecBuf = decrypted.data();
            uint32 decBufSz = decrypted.size();

            // decompression inflate
            std::vector<uint8> outVector;

            if (true) // si le fichier est compressé (pas le cas pour les png)
            {
                z_stream inflateStr = {};
                inflateStr.zalloc = 0;
                inflateStr.zfree = 0;
                inflateStr.next_in = (uint8_t*)pDecBuf;
                inflateStr.avail_in = (uint32)decBufSz;
                int err = inflateInit_(&inflateStr, ZLIB_VERSION, (int)sizeof(inflateStr));

                inflateStr.avail_in = decBufSz;
                inflateStr.next_in = pDecBuf;

                uint8 decompressStack[2048];
                for (;;)
                {
                    inflateStr.next_out = (Bytef*)decompressStack;
                    inflateStr.avail_out = (uint32)sizeof(decompressStack);

                    int ret = inflate(&inflateStr, Z_NO_FLUSH);

                    uint32 szDecompress = sizeof(decompressStack) - inflateStr.avail_out;
                    if (szDecompress == 0)
                        break;

                    outVector.insert(outVector.end(), decompressStack, decompressStack + szDecompress);

                    if (ret == Z_STREAM_END)
                        break;
                }

                err = inflateEnd(&inflateStr);
            }
            else
            {
                outVector = decrypted;
            }


            HANDLE hOut = CreateFileA("C:\\Users\\Unknown8192\\Desktop\\OUT.nty", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
            WriteFile(hOut, outVector.data(), outVector.size(), &reads, 0);
            FlushFileBuffers(hOut);
            CloseHandle(hOut);
        }
    }

    Sleep(1000000);



    // Exemple de déchiffrement des données
    {
        printf("Test de dechiffrement des donnees :\n");

        // Mettre les données à déchiffrer ici
        const char* DataToDecrypt = "IbiObF5TlhPOGuMjZI,ukyvc9ZAshH..c6HTU2UeTuPBwAQNx6hUwx4HHAcS.7PHFdDn4dYUsBdPIHLQDDpdZ3oVWjdvFnes3Xy3sp9eb7JEBgXtRgzg.yotD22sDDnF2BiRtfE1LIRWXgj8uPKs63g2XAxNenLcrIZzVcbIv2R5a3Q1N7UYwAtAkm0cKq.lgJS3RFdTQ3RkuxEIxUM3sw__";

        // Mettre la clé à utiliser ici (la clé initiale est: vuyWQSjlknpJF54ib36txVse)
        const char* KeyToUse = "vuyWQSjlknpJF54ib36txVse";
        // keyToUse = 7cb9c92b9f899b69d312aaaf (bq159_key envoyé par le serveur dans la capture Charles)


        // Décodage des données en r-base64
        auto bin = RB64Decode(DataToDecrypt);

        // Création d'un contexte de chiffrement MD159
        // et initialisation de la clé dans celui-ci
        MD159 ctx = {};
        ctx.InitializeKey(KeyToUse, strlen(KeyToUse));

        /*
            Petite précision :
                
                Dans la réponse à la requête "/users/sessions" renvoyé par le serveur
                se trouve la nouvelle clé de chiffrement (la valeur de la clé JSON "bq159_key").

                A ce moment là de la connexion, pour utiliser la nouvelle clé défini par le serveur,
                tout ce que vous avez à faire est d'appeler :

                    ctx.InitializeKey(myJson["bq159_key"], myJson["bq159_key"].length());
        */

        // Déchiffrement des données
        std::vector<uint8> decrypted;
        ctx.Decrypt(bin.data(), bin.size(), decrypted);


        // Affichage des données déchiffrés
        printf("\n");
        PrintHexLine(decrypted.data(), decrypted.size());
    }


    printf("\n\n\n");


    // Exemple de chiffrement des données
    {
        printf("Test de chiffrement des donnees :\n");

        // Mettre les données à chiffrer ici
        const char* DataToEncrypt = "Bonjour MD159! C'est un simple test de chiffrement sur plusieurs blocs de 16 octets.";
        int DataToEncryptLen = strlen(DataToEncrypt);

        // Mettre la clé à utiliser ici
        const char* KeyToUse = "vuyWQSjlknpJF54ib36txVse";
        

        // Création d'un contexte de chiffrement MD159
        // et initialisation de la clé dans celui-ci
        MD159 ctx = {};
        ctx.InitializeKey(KeyToUse, strlen(KeyToUse));

        // Chiffrement des données
        std::vector<uint8> encrypted;
        ctx.Encrypt((const uint8*)DataToEncrypt, DataToEncryptLen, encrypted);


        // Affichage des données chiffrés
        printf("\n");
        std::string rb64Data = RB64Encode(encrypted.data(), encrypted.size());
        printf("%s", rb64Data.c_str());
    }


    /*
        Note additionnelle :
    
            Les données chiffrés sont effectivement des chaines de caractères JSON,
            alors il ne faut pas oublier d'ajouter par sécurité un null-byte finale
            dans le vector "decrypted" avant de chercher à le transformer en std::string,
            car celui-ci n'en contient pas systématiquement un.
    */


    printf("\n\n\n\n");
    Sleep(10000000);

	return 0;
}