# DLL Injector

## Method
This DLL injector uses the most reliable method for hooking the DLL into a process is to use the kernel32.dll library and make use of the LoadLibraryA method. 

- The names for the DLL and process names from the cmdline of the console created by the application.
- The process is identified from the snapshot taken while the application is running.
- Once the handle for the process is found then the process is opened with administration privileges.
- Memory is allocated in the process and the path to the DLL is written to the memory.
- Then the DLL Injector gets the memory address for the LoadLibraryA function loaded into memory from the kernel32.dll library.
- A call is made to CreateRemoteThread to spawn a thread for the module and the DLL path is provided within the memory of the process itself