#include "SigScanner.h"
#include <Psapi.h>

constexpr Signature::Signature(DWORD Flg, const char* Sig, const char* Msk): Flags(Flg), Siggy(Sig), Mask(Msk), Len(KStrlen(Msk)), Result(0) { }

bool Signature::Empty() const {
	return Result == 0;
}

bool SigScanner::Compare(const char* Sig, const char* Mask, const char* Loc) {
	for (; *Mask; Mask++, Sig++, Loc++) {
		if (*Mask == 'x' && *Sig != *Loc) {
			return false;
		}
	}

	return true;
}

void SigScanner::QueueCode(const char* Sig, const char* Mask) {
	Sigs.push_back(Signature(EXEC_PAGES, Sig, Mask));
}

void SigScanner::QueueData(const char* Sig, const char* Mask) {
	Sigs.push_back(Signature(PAGE_READONLY, Sig, Mask));
}

void* SigScanner::ScanCode(const char* Sig, const char* Mask) {
	auto& Pages = Memory->Pages;
	const size_t Len = KStrlen(Mask);

	for (size_t Idx = 0; Idx < Pages.size(); Idx++) {
		auto& Pg = Pages[Idx];

		if (Pg.Flags & EXEC_PAGES) {
			const size_t End = Pg.End - Len;
			for (size_t Bt = Pg.Start; Bt < End; Bt++) {
				if (SigScanner::Compare(Sig, Mask, (const char*)Bt)) {
					return (void*)Bt;
				}
			}
		}
	}

	return NULL;
}

void* SigScanner::GetAddress(int Addr) const {
	return Sigs[Addr].Result;
}

void SigScanner::ScanSigs() {
	auto& Pages = Memory->Pages;
	for (size_t Idx = 0; Idx < Pages.size(); Idx++) {
		auto& Pg = Pages[Idx];
		bool Done = true;

		for (size_t Sg = 0; Sg < Sigs.size(); Sg++) {
			Signature& Sig = Sigs[Sg];

			if (Sig.Empty()) {
				if (Pg.Flags & Sig.Flags) {
					for (DWORD Start = Pg.Start, End = Pg.End - Sig.Len; Start < End; Start++) {
						if (SigScanner::Compare(Sig.Siggy, Sig.Mask, (const char*)Start)) {
							Sig.Result = (void*)Start;
							break;
						}
					}
				}
				if (Sig.Empty()) {
					Done = false;
				}
			}
		}

		if (Done) {
			break;
		}
	}
}

SigScanner::SigScanner(MemoryPages* Pages): Memory(Pages) {
	Sigs.clear();
}