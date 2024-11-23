#include "dbg.h"
#include <Shlwapi.h>

namespace Debug {
	OutputTypes output_type;
	CRITICAL_SECTION CS = { 0 };
	HANDLE dbg_file_handle = 0;

	bool Init(OutputTypes type) {
		output_type = type;

		if (type == OutputTypes::kFile) {
			InitializeCriticalSection(&CS);

			dbg_file_handle = CreateFileW(L"C:\\ProgramData\\fastldr.log", GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, 0);

			if (dbg_file_handle == INVALID_HANDLE_VALUE) {
				return FALSE;
			}

			WORD bom = 0xFEFF;
			DWORD written = 0;

			WriteFile(dbg_file_handle, &bom, sizeof(bom), &written, NULL);
		}

		return TRUE;
	}

	void OutToDbg(LPCWSTR message_text, va_list args) {
		WCHAR dbg_message[1025] = { 0 };

		wvsprintfW(dbg_message, message_text, args);
		OutputDebugStringW(dbg_message);
	}

	void OutToFile(LPCWSTR message_text, va_list args) {
		EnterCriticalSection(&CS);

		WCHAR dbg_message[1025] = { 0 };
		int char_count = wvsprintfW(dbg_message, message_text, args);
		DWORD written = 0;


		WriteFile(dbg_file_handle, dbg_message, char_count * 2, &written, nullptr);
		WriteFile(dbg_file_handle, L"\r\n", 4, &written, nullptr);
		LeaveCriticalSection(&CS);
	}

	void DebugMsg(LPCWSTR message_text, ...) {
		va_list args = nullptr;

		va_start(args, message_text);

		switch (output_type) {
		case OutputTypes::kDbgConsole:
			OutToDbg(message_text, args);
		case OutputTypes::kFile:
			OutToFile(message_text, args);
		default:
			break;
		}

		va_end(args);
	}
}