#include "MemPaging.h"
#include <Psapi.h>

MemoryPages::Page::Page(DWORD F, DWORD S, DWORD E): Flags(F), Start(S), End(E) {}

MemoryPages::MemoryPages(const char* Module, DWORD Flags): Flags(Flags) {
	MODULEINFO Info;

	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(Module), &Info, sizeof(Info));

	Start = (DWORD)Info.lpBaseOfDll;
	End = Start + Info.SizeOfImage;
}

DWORD MemoryPages::GetBase() const {
	return Start;
}

void MemoryPages::Refresh() {
	MEMORY_BASIC_INFORMATION PageData;
	DWORD PageAddy = Start;
	
	Pages.clear();

	while (VirtualQuery((LPCVOID)PageAddy, &PageData, sizeof(PageData))) {
		DWORD Base = (DWORD)PageData.BaseAddress;
		DWORD PageEnd = Base + PageData.RegionSize;

		if (PageData.Protect & Flags) {
			Pages.push_back(Page(PageData.Protect, Base, PageEnd));
		}
		PageAddy = PageEnd;

		if (PageAddy > End) {
			break;
		}
	}
}
