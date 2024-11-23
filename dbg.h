#pragma once

#include <Windows.h>

#ifdef _DEBUG
#define DBGPRINT(message, ...) \
	Debug::DebugMsg(message, __VA_ARGS__);
#else
#define DBGPRINT(message, ...) \
	Debug::DebugMsg(message, __VA_ARGS__);
#endif

namespace Debug {
	enum OutputTypes {
		kDbgConsole,
		kFile
	};

	bool Init(OutputTypes type);

	void DebugMsg(LPCWSTR message_text, ...);
}