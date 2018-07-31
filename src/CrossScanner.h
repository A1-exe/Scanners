#pragma once
#include "SigScanner.h"
#include <Windows.h>
#include <vector>
#include <unordered_map>

struct Operation {
	BYTE Opcode;
	DWORD Operand;
	DWORD Function;
};

enum NodeType {
	RefString, RefSubroutine,
	RefCaller
};

struct Node {
	NodeType Type; // is string or sub?
	size_t Hash;
	union {
		const char* Str;
		int Sub; // value
	};
};

class Path {
private:
	std::vector<Node> Nodes;

public:
	std::vector<Node>& GetNodes();
	Path& operator<<(const char* Str);
	Path& operator<<(int Sub);
};

class CrossScanner {
private:
	const MemoryPages* Memory;
	std::vector<Path> Paths;
	std::vector<Operation> Code;
	std::unordered_map<size_t, void*> Cached;

	void SearchCodePage(DWORD Start, DWORD End);
	void* GenericSearch(DWORD Addy, BYTE Opcode);
	void* LookupCall(DWORD Base, size_t Call);

public:
	void* Traverse(Path& P);
	CrossScanner(MemoryPages* Pages);
};