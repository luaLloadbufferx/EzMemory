# EzMemory
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Windows](https://img.shields.io/badge/Platform-Windows-0078d7.svg)](https://www.microsoft.com/windows)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/)

**EzMemory** is a lightweight, NTAPI-based memory manipulation library for Windows. Built for reverse engineering, game modding, and debugging tools; with clean syntax and multi-process support.

## Quick start
```cpp
#include "easymem.hpp"
#include <iostream>

int main() {
	/*
	 Initializes EzMem. You must call this exactly once at the start.
	*/
	EzMem::Initialize();

	/*
	 Attaches EasyMem to the target process.
	 Args:
	 ProcName - Target process name.
	 Access - What rights will the handle get (default: EZMEM_DEFAULT_RIGHTS)
	 Returns:
	 EzMemProcess instance.
	*/
	EzMemProcess Process = EzMem::Attach(L"notepad.exe");
	std::cout << "hProcess: 0x" << std::hex << Process.hProc << std::endl;
	std::cout << "Base: 0x" << std::hex << Process.base << std::endl;

	/*
	 Allocates X bytes of memory to the target process.
	 Args:
	 EzMemProcess instance.
	 Size - Amount of bytes to allocate.
	 Protection - Protection of the page (default: PAGE_READWRITE).
	 Returns:
	 Address of the allocated memory.
	*/
	uintptr_t address = EzMem::Allocate(Process, 4);

	/*
	 Writes a specified value.
	 Args:
	 EzMemProcess instance.
	 address.
	 Value.
	 Usage:
	 Write<type>(Process, address, value);
	*/
	EzMem::Write<int>(Process, address, 1337);

	/*
	 Reads a specified value.
	 Args:
	 EzMemProcess instance.
	 Address.
	*/
	auto val = EzMem::Read<int>(Process, address);
	
	std::cout << "Value: " << std::dec << val << std::endl;

	/*
 	 Detaches the EzMemProcess instance.
 	 Args:
 	 EzMemProcess instance.
 	 FreeMemory - Free all allocated memory from this instance? (boolean, defaults to true).
	*/
	EzMem::Detach(Process, true);

	return 0;
}
