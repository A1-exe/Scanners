#include "CrossScanner.h"
#include "hde32.h"
#include <functional>

#define SIZE_INSTR 0x10 /* safe offset */
#define CALL_OFF_OP 0xE8
#define PUSH_OFF_OP 0x68

const std::hash<std::string> HashString;

std::vector<Node>& Path::GetNodes() {
	std::string Hasher;
	for (size_t Idx = 0; Idx < Nodes.size(); Idx++) {
		Node& N = Nodes[Idx];
		if (N.Hash == 0) {
			if (N.Type == RefString) {
				Hasher.append(N.Str);
			}
			else {
				Hasher += N.Sub;
			}
			N.Hash = HashString(Hasher);
		}
	}
	return Nodes;
}

Path& Path::operator<<(const char* Str) {
	Node N;
	N.Type = RefString;
	N.Str = Str;
	N.Hash = 0;
	Nodes.push_back(N);
	return *this;
}

Path& Path::operator<<(int Sub) {
	Node N;
	if (Sub == -1) {
		N.Type = RefCaller;
	}
	else {
		N.Type = RefSubroutine;
		N.Sub = Sub;
	}
	N.Hash = 0;
	Nodes.push_back(N);
	return *this;
}

void CrossScanner::SearchCodePage(DWORD Start, DWORD End) {
	hde32s Inst;
	Code.clear();
	End -= SIZE_INSTR;
	while (Start < End) {
		DWORD Base = Start;

		if (Start % 0x10) { // alignment
			Start += 0x10 - Start % 0x10;
			continue;
		}


		if (memcmp((void*)Start, "\x55\x8B\xEC", 3)) { // push ebp && mov ebp, esp
			Start += 0x10;
			continue;
		}

		while (Start < End) {
			Start += hde32_disasm((void*)Start, &Inst);

			if (Inst.flags & F_ERROR) {
			exit_loop:
				break;
			}
			else {
				bool Proceed = false;
				switch (Inst.opcode) {
					//case 0xC3: // ret
					//case 0xC2: // retx
					//case 0xCB: // ref
					//case 0xCA: // retfx
					case 0xCC: // int 3
						goto exit_loop;
					case PUSH_OFF_OP: // operations for lookup
					case CALL_OFF_OP:
						Proceed = true;
						break;
				}

				if (Proceed) {
					Operation Oper;

					if (Inst.flags & F_RELATIVE) {
						Inst.imm.imm32 += Start;
					}

					Oper.Opcode = Inst.opcode;
					Oper.Operand = Inst.imm.imm32;
					Oper.Function = Base;

					Code.push_back(Oper);
				}
			}
		}
	}
}

void* CrossScanner::GenericSearch(DWORD Addy, BYTE Opcode) {
	auto& Pages = Memory->Pages;
	size_t PageNum = 0;

	while (true) {
		bool Finished = true;
		for (size_t Idx = 0; Idx < Code.size(); Idx++) {
			Operation& Op = Code[Idx];

			if ((Op.Opcode == Opcode) && (Op.Operand == Addy)) {
				return (void*)Op.Function;
			}
		}

		while (PageNum < Pages.size()) {
			auto& Pg = Pages[PageNum++];
			if (Code.size() && ((Code.front().Function > Pg.End) || (Code.back().Function < Pg.Start))) {
				continue;
			}
			SearchCodePage(Pg.Start, Pg.End);
			Finished = false;
		}

		if (Finished) {
			break;
		}
	}

	return NULL;
}

void* CrossScanner::LookupCall(DWORD Base, size_t Call) {
	size_t Start = 0;

	if ((Code.front().Function > Base) || (Code.back().Function < Base)) {
		auto& Pages = Memory->Pages;
		for (size_t Idx = 0; Idx < Pages.size(); Idx++) {
			auto& Page = Pages[Idx];
			if ((Page.Start <= Base) && (Page.End >= Base)) {
				SearchCodePage(Base, Page.End);
				break;
			}
		}
	}
	else {
		for (size_t Idx = 0; Idx < Code.size(); Idx++) {
			if (Code[Idx].Function == Base) {
				Start = Idx;
				break;
			}
		}
	}

	for (; Start < Code.size(); Start++) {
		Operation& Op = Code[Start];
		if (Op.Function != Base) {
			break;
		}
		else if (Op.Opcode == CALL_OFF_OP) {
			if (!Call--) {
				return (void*)Op.Operand;
			}
		}
	}

	return NULL;
}

void* CrossScanner::Traverse(Path& P) {
	std::vector<Node>& Nodes = P.GetNodes();
	void* Last = NULL;

	for (size_t Idx = 0; Idx < Nodes.size(); Idx++) {
		Node& N = Nodes[Idx];
		void* Now = NULL;

		if (Cached.find(N.Hash) != Cached.end()) {
			Now = Cached.at(N.Hash);
		}
		else {
			switch (N.Type) {
				case RefString:
					Now = GenericSearch((DWORD)N.Str, PUSH_OFF_OP);
					break;
				case RefSubroutine:
					Now = LookupCall((DWORD)Last, N.Sub);
					break;
				case RefCaller:
					Now = GenericSearch((DWORD)Last, CALL_OFF_OP);
					break;
			}
		}

		if (Now) {
			Cached.insert({N.Hash, Now});
			if ((Idx + 1) == Nodes.size()) {
				return Now;
			}
			else {
				Last = Now;
			}
		}
		else {
			break;
		}
	}

	return NULL;
}

CrossScanner::CrossScanner(MemoryPages* Pages): Memory(Pages) { }