#pragma once
#include "MemPaging.h"
#include <Windows.h>
#include <vector>

constexpr int KStrlen(const char* Type) { // Helps out with initializing
	return *Type ? KStrlen(Type + 1) + 1 : 0;
}

struct Signature {
	const size_t Len;
	const DWORD Flags;
	const char* const Siggy;
	const char* const Mask;
	void* Result;
	constexpr Signature(DWORD Flg, const char* Sig, const char* Msk);
	bool Empty() const;
};

class SigScanner {
private:
	const MemoryPages* Memory;
	std::vector<Signature> Sigs;

	static bool Compare(const char* Sig, const char* Mask, const char* Loc);
	
public:
	void QueueCode(const char* Sig, const char* Mask);
	void QueueData(const char* Sig, const char* Mask);
	void* ScanCode(const char* Sig, const char* Mask);
	void* GetAddress(int Addr) const;
	void ScanSigs();
	SigScanner(MemoryPages* Pages);
};