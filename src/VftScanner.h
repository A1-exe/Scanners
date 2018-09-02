#pragma once
#include <unordered_map>
#include <Windows.h>

class VftScanner {
private:
	std::unordered_map<void*, void*> Cached;
	HANDLE Heap;
public:
	void* Find(void* Vftable, size_t Size);
	VftScanner();
};