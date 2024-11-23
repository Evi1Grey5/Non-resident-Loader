#include "network.h"
#include "dbg.h"
#include "memory.h"
#include <WinInet.h>

namespace Network {
	bool DownloadFile(
		__in LPCWSTR url,
		__in LPCWSTR file_path
	) {
		BOOL ret = false;
		HINTERNET inet_handle = 0;
		HINTERNET url_handle = 0;
		HANDLE file_handle = 0;

		do
		{
			WCHAR user_agent[] = { 'M', 'o', 'z', 'i', 'l', 'l', 'a', '/', '5', '.', '0', ' ', '(', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'N', 'T', ' ', '1', '0', '.', '0', ';', ' ', 'W', 'i', 'n', '6', '4', ';', ' ', 'x', '6', '4', ')', ' ', 'A', 'p', 'p', 'l', 'e', 'W', 'e', 'b', 'K', 'i', 't', '/', '5', '3', '7', '.', '3', '6', ' ', '(', 'K', 'H', 'T', 'M', 'L', ',', ' ', 'l', 'i', 'k', 'e', ' ', 'G', 'e', 'c', 'k', 'o', ')', ' ', 'C', 'h', 'r', 'o', 'm', 'e', '/', '1', '3', '1', '.', '0', '.', '0', '.', '0', ' ', 'S', 'a', 'f', 'a', 'r', 'i', '/', '5', '3', '7', '.', '3', '6', 0, 0 };

			inet_handle = InternetOpenW(user_agent, INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);

			if (!inet_handle) {
				DBGPRINT(L"File %s, line %d, InternetOpenW error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}

			url_handle = InternetOpenUrlW(inet_handle, url, nullptr, 0, 0, 0);

			if (!url_handle) {
				DBGPRINT(L"File %s, line %d, InternetOpenUrlW error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}

			file_handle = CreateFileW(file_path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, 0);

			if (file_handle == INVALID_HANDLE_VALUE) {
				DBGPRINT(L"File %s, line %d, CreateFileW error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}

			while (true) {
				byte buffer[4096] = { 0 };
				DWORD read = 0;

				if (!InternetReadFile(url_handle, buffer, 4096, &read)) {
					DBGPRINT(L"File %s, line %d, InternetReadFile error %d", __FILEW__, __LINE__, GetLastError());
					break;
				}

				if (!read) {
					ret = true;
					break;
				}

				DWORD written = 0;

				if (!WriteFile(file_handle, buffer, read, &written, nullptr)) {
					DBGPRINT(L"File %s, line %d, WriteFile error %d", __FILEW__, __LINE__, GetLastError());
					break;
				}
			}
		} while (false);

		if (inet_handle) {
			InternetCloseHandle(inet_handle);
		}

		if (url_handle) {
			InternetCloseHandle(url_handle);
		}

		if (file_handle) {
			InternetCloseHandle(file_handle);
		}

		return ret;
	}

	bool DownloadFileToMem(
		__in LPCWSTR url,
		__out PBYTE* data,
		__out PDWORD data_size
	) {
		BOOL ret = false;
		HINTERNET inet_handle = 0;
		HINTERNET url_handle = 0;

		do
		{
			WCHAR user_agent[] = { 'M', 'o', 'z', 'i', 'l', 'l', 'a', '/', '5', '.', '0', ' ', '(', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'N', 'T', ' ', '1', '0', '.', '0', ';', ' ', 'W', 'i', 'n', '6', '4', ';', ' ', 'x', '6', '4', ')', ' ', 'A', 'p', 'p', 'l', 'e', 'W', 'e', 'b', 'K', 'i', 't', '/', '5', '3', '7', '.', '3', '6', ' ', '(', 'K', 'H', 'T', 'M', 'L', ',', ' ', 'l', 'i', 'k', 'e', ' ', 'G', 'e', 'c', 'k', 'o', ')', ' ', 'C', 'h', 'r', 'o', 'm', 'e', '/', '1', '3', '1', '.', '0', '.', '0', '.', '0', ' ', 'S', 'a', 'f', 'a', 'r', 'i', '/', '5', '3', '7', '.', '3', '6', 0, 0 };

			inet_handle = InternetOpenW(user_agent, INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);

			if (!inet_handle) {
				DBGPRINT(L"File %s, line %d, InternetOpenW error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}

			url_handle = InternetOpenUrlW(inet_handle, url, nullptr, 0, 0, 0);

			if (!url_handle) {
				DBGPRINT(L"File %s, line %d, InternetOpenUrlW error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}

			DWORD total = 0;

			while (true) {
				byte buffer[4096] = { 0 };
				DWORD read = 0;

				if (!InternetReadFile(url_handle, buffer, 4096, &read)) {
					DBGPRINT(L"File %s, line %d, InternetReadFile error %d", __FILEW__, __LINE__, GetLastError());
					break;
				}

				if (!read) {
					*data_size = total;
					ret = true;
					break;
				}

				if (!*data) {
					*data = (PBYTE)Memory::Alloc(read);
				}
				else {
					*data = (PBYTE)Memory::ReAlloc(*data, total + read);
				}

				if (!*data) {
					DBGPRINT(L"File %s, line %d, alloc error %d", __FILEW__, __LINE__, GetLastError());
					break;
				}
				
				memcpy(*data + total, buffer, read);

				total += read;
			}
		} while (false);

		if (inet_handle) {
			InternetCloseHandle(inet_handle);
		}

		if (url_handle) {
			InternetCloseHandle(url_handle);
		}

		return ret;
	}
}