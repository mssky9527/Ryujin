#pragma once
#include <Zydis/Zydis.h>
#include <Zydis/SharedTypes.h>
#include <vector>
#include "../Models/RyujinBasicBlock.hh"

class RyujinBasicBlockerBuilder {

private:
	ZydisDecoder decoder;
	bool isControlFlow(const ZydisDecodedInstruction& instruction) const;

public:
	RyujinBasicBlockerBuilder(ZydisMachineMode machine, ZydisStackWidth stack);
	std::vector<RyujinBasicBlock> createBasicBlocks(const unsigned char* chOpcode, size_t szOpcode, uintptr_t start_address);

};