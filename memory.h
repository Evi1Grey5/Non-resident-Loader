#pragma once

#include <Windows.h>

namespace Memory {
	bool Init();

	void* Alloc(DWORD size);

	void* ReAlloc(void* ptr, DWORD size);

	bool Free(void* ptr);
}