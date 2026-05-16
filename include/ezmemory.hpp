/*
MIT License

Copyright (c) 2026 luaLloadbufferx

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// https://github.com/luaLloadbufferx/EzMemory

#pragma once
#include <Windows.h>
#include <vector>
#include <string>

#define EZMEM_DEFAULT_RIGHTS (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION)
#define EZMEM_INJECT_RIGHTS (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)

struct EzMemProcess {
	HANDLE hProc;
	DWORD pid;
	uintptr_t base;
	SIZE_T read;
	SIZE_T written;
	NTSTATUS LastStatus;
	std::vector<uintptr_t> allocations;

	EzMemProcess(const EzMemProcess&) = delete;
	EzMemProcess& operator=(const EzMemProcess&) = delete;

	EzMemProcess(EzMemProcess&&) noexcept = default;
	EzMemProcess& operator=(EzMemProcess&&) noexcept = default;

	EzMemProcess() : hProc(nullptr), pid(0), base(0), read(0), written(0), LastStatus(0) {};
};

namespace EzMem {
	/*
	 Initializes EzMem.
	*/
	void Initialize();

	/*
	 Detaches the EzMemProcess instance.
	 Args:
	 EzMemProcess instance.
	 FreeMemory - Free all allocated memory from this instance? (boolean)
	*/
	void Detach(EzMemProcess& Process, bool FreeMemory = true);

	/*
	 Attaches EzMemory to the target process.
	 Args:
	 ProcName - Target process name.
	 Returns:
	 EzMemProcess instance.
	 Access - What rights will the handle get (default: EZMEM_DEFAULT_RIGHTS)
	*/
	EzMemProcess Attach(const wchar_t* ProcName, DWORD Access = EZMEM_DEFAULT_RIGHTS);

	/*
	 Allocates X bytes of memory to the target process.
	 Args:
	 EzMemProcess instance.
	 Size - Amount of bytes to allocate (default: 1 PAGE).
	 Protection - Protection of the page (default: PAGE_READWRITE).
	 Returns:
	 Address of the allocated memory.
	*/
	uintptr_t Allocate(EzMemProcess& Process, SIZE_T Size = 4096, DWORD Protection = PAGE_READWRITE);

	/*
	 Frees the allocation at the specified address.
	 Args:
	 EzMemProcess instance.
	 Address.
	 Returns:
	 Succeeded boolean.
	*/
	bool Free(EzMemProcess& Process, uintptr_t address);

	/*
	 The extended version of Read.
	 Reads a specified value.
	 Args:
	 EzMemProcess instance.
	 Address.
	 Buffer.
	 Size of the value.
	 Returns:
	 Read value.
	*/
	bool ReadEx(EzMemProcess& Process, uintptr_t address, void* buffer, SIZE_T size);

	/*
	 Reads a specified value.
	 Args:
	 EzMemProcess instance.
	 Address.
	 Returns:
	 Read value.
	 Usage:
	 Read<type>(Process, address);
	*/
	template <typename T>
		requires std::is_trivially_copyable_v<T>
	T Read(EzMemProcess& Process, uintptr_t address) {
		T value{};
		if (!EzMem::ReadEx(Process, address, &value, sizeof(T))) {
			return T{};
		}
		return value;
	}

	/*
	 The extended version of Write.
	 Writes a value to the specified address.
	 Args:
	 EzMemProcess instance.
	 Address.
	 Buffer.
	 Size of the value.
	*/
	bool WriteEx(EzMemProcess& Process, uintptr_t address, const void* buffer, SIZE_T size);

	/*
	 Writes a specified value.
	 Args:
	 EzMemProcess instance.
	 address.
	 Value.
	 Usage:
	 Write<type>(Process, address, value);
	*/
	template <typename T>
		requires std::is_trivially_copyable_v<T>
	void Write(EzMemProcess& Process, uintptr_t address, const T& value) {
		EzMem::WriteEx(Process, address, &value, sizeof(T));
		return;
	}

	/*
	 Resolves a pointer chain.
	 Args:
	 EzMemProcess instance.
	 base.
	 offsets array.
	 Returns:
	 Address of the value at the end of the chain.
	*/
	template<typename T = uintptr_t>
	T ResolvePointerChain(EzMemProcess& Process, uintptr_t base, const std::vector<uintptr_t>& offsets) {
		if (offsets.empty()) {
			return (T)base;
		}
		uintptr_t current = base;
		for (size_t i = 0; i < offsets.size() - 1; i++) {
			if (!ReadEx(Process, current + offsets[i], &current, sizeof(current))) {
				return (T)0;
			}
		}
		return (T)(current + offsets.back());
	}

	/*
	 Read a pointer chain.
	 Args:
	 EzMemProcess instance.
	 base.
	 offsets array.
	 Returns:
	 Value of the address at the end of the chain.
	*/
	template <typename T>
	T ReadChain(EzMemProcess& Process, uintptr_t base, const std::vector<uintptr_t>& offsets) {
		uintptr_t addr = ResolvePointerChain(Process, base, offsets);
		if (!addr) {
			return T{};
		}
		return EzMem::Read<T>(Process, addr);
	}

	/*
	 Write to a pointer chain.
	 Args:
	 EzMemProcess instance.
	 base.
	 offsets array.
	 Value.
	 Returns:
	 Did we succeed writing? (boolean)
	*/
	template <typename T>
	bool WriteChain(EzMemProcess& Process, uintptr_t base, const std::vector<uintptr_t>& offsets, const T& value) {
		uintptr_t addr = ResolvePointerChain<uintptr_t>(Process, base, offsets);
		if (!addr) {
			return false;
		}
		EzMem::Write<T>(Process, addr, value);
		return (Process.LastStatus == 0x0);
	}

	/*
	 Get the base address of a module.
	 Args:
	 EzMemProcess instance.
	 ModuleName (wchar_t)
	 Returns:
	 Base address (uintptr_t)
	*/
	uintptr_t GetModule(EzMemProcess& Process, const wchar_t* ModuleName);

	/*
	 Change the protection of a specified address and size.
	 Args:
	 EzMemProcess instance.
	 address.
	 size.
	 protection.
	 Returns:
	 Old Protection.
	*/
	DWORD Protect(EzMemProcess& Process, uintptr_t address, SIZE_T size, DWORD protection);

	/*
	 Inject a DLL with the LoadLibraryW method.
	 Args:
	 EzMemProcess instance.
	 DllPath.
	 Returns:
	 Succeeded boolean.
	*/
	bool LoadLibraryInject(EzMemProcess& Process, const wchar_t* DllPath);

} // namespace EzMem
