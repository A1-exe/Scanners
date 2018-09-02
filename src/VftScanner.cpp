#include "VftScanner.h"
// Special thanks to Brandon (Chirality) for the original
// concept and code for this scanner. This is a slightly
// altered version.

void* VftScanner::Find(void* Vftable, size_t Size) {
	void* Return = NULL;

	if (Cached.find(Vftable) == Cached.end()) {
		PROCESS_HEAP_ENTRY HeapEntry;

		ZeroMemory(&HeapEntry, sizeof(HeapEntry));
		HeapLock(Heap);

		while (HeapWalk(Heap, &HeapEntry)) { // +4 internal bytes
			if (HeapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
				if (HeapEntry.cbData < Size)
					continue;

				DWORD Data = (DWORD)HeapEntry.lpData + 4;

				if (*(DWORD*)Data == (DWORD)Vftable) {
					Cached.insert({Vftable, (void*)Data});
					Return = (void*)Data;
					break;
				}
			}
		}

		HeapUnlock(Heap);
	}
	else {
		Return = Cached.at(Vftable);
	}

	return Return;
}

VftScanner::VftScanner(): Heap(GetProcessHeap()) { }