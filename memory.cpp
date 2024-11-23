#include "memory.h"

namespace Memory {
	HANDLE heap_handle = 0;

	bool Init() {
		return ((heap_handle = GetProcessHeap()) != nullptr);
	}

	void* Alloc(DWORD size) {
		return HeapAlloc(heap_handle, HEAP_ZERO_MEMORY, size);
	}

	void* ReAlloc(void* ptr, DWORD size) {
		return HeapReAlloc(heap_handle, HEAP_ZERO_MEMORY, ptr, size);
	}

	bool Free(void* ptr) {
		return HeapFree(heap_handle, 0, ptr);
	}
}