#pragma once
#include <Windows.h>
#include <vector>
#include <set>
#include <cstdint>
#include <unordered_map>
#include <asmjit/asmjit.h>
#include <Zydis/Zydis.h>
#include <Zydis/SharedTypes.h>
#include "../Models/RyujinProcedure.hh"
#include "../Models/RyujinObfuscatorConfig.hh"
#include "../RyujinCore/BasicBlockerBuilder.hh"

class RyujinObfuscationCore {

private:
	const int MAX_PADDING_SPACE_INSTR = 50;
	std::vector<ZydisRegister> m_unusedRegisters;
	std::vector<RyujinBasicBlock> m_obfuscated_bb;
	RyujinProcedure m_proc;
	BOOL extractUnusedRegisters();
	void addPaddingSpaces();
	std::vector<uint8_t> fix_branch_near_far_short(uint8_t original_opcode, uint64_t jmp_address, uint64_t target_address);

public:
	RyujinObfuscationCore(const RyujinObfuscatorConfig& config, const RyujinProcedure& proc);
	uint32_t findOpcodeOffset(const uint8_t* data, size_t dataSize, const void* opcode, size_t opcodeSize);
	void applyRelocationFixupsToInstructions(uintptr_t imageBase, DWORD virtualAddress, std::vector<unsigned char>& new_opcodes);
	BOOL Run();
	RyujinProcedure getProcessedProc();
	~RyujinObfuscationCore();

};