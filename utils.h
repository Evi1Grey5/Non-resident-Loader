#pragma once

#include <Windows.h>

namespace Utils {
	DWORD GetIntegrityLevel();

	bool ElevateUAC(LPCWSTR file_path);

	bool IsElevated();
}