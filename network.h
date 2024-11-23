#pragma once

#include <Windows.h>

namespace Network {
	bool DownloadFile(
		__in LPCWSTR url,
		__in LPCWSTR file_path
	);

	bool DownloadFileToMem(
		__in LPCWSTR url,
		__out PBYTE* data,
		__out PDWORD data_size
	);
}