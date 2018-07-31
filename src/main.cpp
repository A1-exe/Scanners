// Example implementation and tests.

#include <iostream>
#include "MemPaging.h"
#include "SigScanner.h"
#include "VftScanner.h"
#include "CrossScanner.h"

void SomePrintCall(const char* Test) {
	printf("Called... %s\n", Test);
}

int main() {
	MemoryPages Pages(NULL, PAGE_READONLY | EXEC_PAGES); // Custom memory page handling
	SigScanner Sig(&Pages);
	CrossScanner Cross(&Pages);
	VftScanner Vft;
	
	Path Caller;
	// Path object for cross referencing
	
	void* Instance;
	void* Code;
	void* Func;
	// Variables

	Pages.Refresh();
	// Called ONCE to get the memory page BOUNDARIES

	Sig.QueueCode("\xCC\xCC\xCC\x00\xCC", "xxx?x"); // example code queueing
	Sig.QueueCode("\xC3\x00\x00\x00\xE8", "x???x");
	Sig.QueueData("Called...", "xxxxxxxxx"); // in SomePrintCall
	Sig.QueueData("Meme?", "xxxxx");
	// Queue scans of different types using the
	// classic signature/mask approach, and optimized
	// for scanning in batches.
	
	Sig.ScanSigs();
	// Scan for everything currently in the queue.
	// Sig.GetAddress(n) indexes the queue as an array.

	Code = Sig.ScanCode("\xC3\xCC\xCC", "xxx");
	// A simple way of scanning for a piece of code
	// without using the cache.

	Instance = Vft.Find((void*)0xBADF00D, 0x4);
	// This iterates over the heap and retrieves the first
	// object as big or bigger then the `Size` argument
	// whose first 4 bytes (vftable) are the specified argument.
	// Can be chained with the sig scanner to retrieve vftable
	// dynamically from code and then utilize it in the scan.

	Caller << (const char*)Sig.GetAddress(2) << -1 << 1;
	Func = Cross.Traverse(Caller);
	// This scans for a function which references the string
	// we scanned for with the 1st QueueData call (index 2).
	// The `-1` then tells it to find what references the function
	// this string uses, and the `1` then tells it to find the first
	// function that function calls. Cross referencing using call/push
	// instructions.

	printf("Instance: 0x%08x\n", (int)Instance); // Will show NULL in this example because invalid vftable
	printf("Code: 0x%08x\n", (int)Code); // Will show a `ret` ending a function somewhere
	printf("Func: 0x%08x\n", (int)Func); // May show NULL depending on linker settings (jmp not handled) and inline settings
	SomePrintCall("Finished");
	return 0;
}