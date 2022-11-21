#include <Windows.h>
#include <windows.h>
#include <TlHelp32.h>
#include <iostream>

#define DLL_NAME "CSGOHack.dll" // Name of the DLL library used for the mod of the game 
#define CSGO_PROCESS_NAME "csgo.exe" // Name given to the process for the CSGO instance

//Follows the method of injection used by ExtremeInjector, opens the process and uses LoadLibrary and creates a remote thread.
//Code based on https://github.com/adamhlt/DLL-Injector/blob/main/Source/DLL%20Injector/DLL_Injector.cpp and Windows Documentation
//Assumption that the DLL for the hack is in the same directory of the executable

DWORD GetCSGOProcessByName() {
	char processName[260];
	size_t sizeOfProcessName;
	PROCESSENTRY32 processEntry; // holds the process being extracted
	processEntry.dwSize = sizeof(processEntry);
	HANDLE processSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // Creates snapshot of all processes running on the system, which processes can be pulled from
	if (processSnapShot == INVALID_HANDLE_VALUE) { // if failed to create a snapshot of the processes then return -1 as error value
		printf("Invalid Handle Value for creating the process snapshot.\n");
		return -1;  
	} 

	// Process32First must be run to get the first process from the snapshot
	if (!Process32First(processSnapShot, &processEntry)) { // grab the first process from the snapshot and see if it is valid
		printf("Empty process snapshot, Process32First failed.\n");
		return -1; 
	}

	if (lstrcmp(CSGO_PROCESS_NAME, processEntry.szExeFile) == 0) { // Compares the name of the first snapshot process to the CSGO expected process name
		printf("Found the CSGO process ID as %d\n", processEntry.th32ProcessID);
		return processEntry.th32ProcessID;
	}

	while (Process32Next(processSnapShot, &processEntry)) { // run through the entire snapshot until the process name matches the CSGO value
		if (lstrcmp(CSGO_PROCESS_NAME, processEntry.szExeFile) == 0) {
			printf("The CSGO process ID is %d\n", processEntry.th32ProcessID);
			return processEntry.th32ProcessID;
		}
	}
	printf("Run through the list of processes, no match found for %s.\n", CSGO_PROCESS_NAME);
	return -1;
}

int main(int argc, char** argv) {
	FILE* consoleOut;
	freopen_s(&consoleOut, "CONOUT$", "w", stdout);

	HANDLE CSGOProcess; // identifer of a process, specifically the CSGO target
	HMODULE kernelDLLHandle; // find the handle to access the kernel32.dll used by CSGO
	FARPROC loadLibraryAddr;  // function address for the LoadLibrary function to be called as a remote thread

	char fullPathDLL[MAX_PATH]; // fully qualified path for the DLL object being used for the hack, found from DLL_NAME
	LPVOID baseAddrProcessMem; // first page of memory allocated within the process for the LoadLibrary setup
	const DWORD pID = GetCSGOProcessByName(); // try to find the proces ID for CSGO and return it

	if (pID == -1) {
		printf("Failed to find process for CSGO\n");
		goto find_process_failed;
	}

	// find the DLL to inject and write to fullPathDLL
	if (GetFullPathNameA(DLL_NAME, sizeof(fullPathDLL), fullPathDLL, nullptr) == 0) {
		printf("Unable to find fully qualified address for DLL\n");
		goto find_process_failed;
	}
	printf("Full path for DLL: %s\n", fullPathDLL);

	CSGOProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID); // open the process indentified as CSGO with full permissions	
	if (CSGOProcess == INVALID_HANDLE_VALUE) { // check to ensure the process was opened
		printf("Failed trying to open the CSGO process.\n");
		goto find_process_failed;
	}	

	// alloc memory within the process to be written
	// reserves memory with read/write permission within the processes memory space 
	baseAddrProcessMem = VirtualAllocEx(CSGOProcess, nullptr, strlen(fullPathDLL) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
	if (baseAddrProcessMem == nullptr) { 
		printf("Failed to reserve memory within the process for the library path.\n");
		goto find_process_failed;
	}
	printf("Reserved program memory: %p\n", baseAddrProcessMem);

	// write DLL name into the process memory to use LoadLibrary on it 
	if (WriteProcessMemory(CSGOProcess, baseAddrProcessMem, (LPVOID) fullPathDLL, strlen(fullPathDLL) + 1, nullptr) == 0) {
		printf("Error writing the library name into the process memory space.\n");
		goto find_process_failed;
	}

	// kernel32.dll is the library used to load other DLL objects within csgo.exe seen in IDA as (00000000004590C4		LoadLibraryA	KERNEL32) in the imports tab
	// rather than relying on the offset, it can be called using GetModuleHandleA to find the handle for the kernel32.dll used to create interfaces in the CSGOHack.dll
	kernelDLLHandle = GetModuleHandleA("kernel32.dll");
	if (kernelDLLHandle == nullptr) {
		printf("Failed to find kernel32 address within CSGO Process.\n");
		goto find_process_failed;
	}
	printf("");

	loadLibraryAddr = GetProcAddress(kernelDLLHandle, "LoadLibraryA");
	if (loadLibraryAddr == nullptr) {
		printf("Failed to find LoadLibraryA address within CSGO Process.\n");
		goto find_process_failed;
	}
	printf("Load library address: %p\n", loadLibraryAddr);

	// create a remote thread within the application to load the hack library
	HANDLE result = CreateRemoteThread(CSGOProcess, nullptr, 0, (LPTHREAD_START_ROUTINE) loadLibraryAddr, baseAddrProcessMem, 0, nullptr);
	if (result == nullptr | result == INVALID_HANDLE_VALUE) {
		printf("Failed to spawn thread to load the library into CSGO\n");
	}
	WaitForSingleObject(result, INFINITE);

	printf("Injection successful.\n");
	VirtualFreeEx(CSGOProcess, baseAddrProcessMem, strlen(fullPathDLL) + 1, MEM_RELEASE);
	CloseHandle(CSGOProcess);
find_process_failed: // jump point for when something fails, allows for cleaning 
	std::cout << "Press any key to exit..." << std::endl;
	getchar();
	FreeConsole();
	return 0;
}