#pragma once
#include <vector>
#include <Windows.h>

#define EXEC_PAGES (PAGE_EXECUTE | PAGE_EXECUTE_READ)

class MemoryPages {
private:
	const DWORD Flags;
	DWORD Start;
	DWORD End;
	struct Page {
		const DWORD Flags;
		const DWORD Start;
		const DWORD End;
		Page(DWORD F,
			 DWORD S,
			 DWORD E);
	};
public:
	std::vector<Page> Pages;
	MemoryPages(const char* Module, DWORD Flags);
	DWORD GetBase() const;
	void Refresh();
};