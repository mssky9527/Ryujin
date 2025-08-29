#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include "RyujinCore.hh"

void RyujinCustomPassDemo(RyujinProcedure* proc) {

    /*
            This is a sample callback that demonstrates how Ryujin users can register callbacks during its operation/integration to be used with the RyujinCore engine.
            This callback provides direct access to the RyujinProcedure class, which encapsulates all the logic of basic blocks and information about each obfuscated procedure,
            allowing modifications and extensions limited only by the implementer's creativity.
            In this example, the registered callback is used solely to display relevant information about each procedure to be obfuscated, as a demonstration.

            A sample output:
            ----------------------------------------------
            RyujinCustomPassDemo get called for subadd
            subadd has 31 bytes, resides on 0x7ff6c7fd1100, with 1 basic blocks.
            Instructions:
            mov [rsp+0x08], ecx
            mov eax, [rsp+0x08]
            add eax, 0x0A
            mov [rsp+0x08], eax
            mov eax, [rsp+0x08]
            sub eax, 0x02
            mov [rsp+0x08], eax
            mov eax, [rsp+0x08]
            ret
            ----------------------------------------------
    */

    std::printf("----------------------------------------------\n");
    std::printf("RyujinCustomPassDemo get called for %s\n", proc->name.c_str());
    std::printf("%s has %lld bytes, resides on 0x%llx, with %llx basic blocks.\n", proc->name.c_str(), proc->size, proc->address, proc->basic_blocks.size());

    std::printf("Instructions:\n");

    for (auto& block : proc->basic_blocks)
        for (auto& inst : block.instructions)
            std::printf("%s\n", inst.instruction.text);

    std::printf("----------------------------------------------\n");

}

auto print_help() -> void {

    std::cout << R"(Ryujin Obfuscator CLI

Usage:
  RyujinConsole.exe --input <exe_path> --pdb <pdb_path> --output <output_path> [options]

Options:
  --input <exe>             Input binary to obfuscate (required)
  --pdb <pdb>               Path to the PDB file (required)
  --output <exe>            Output path for obfuscated binary (required)
  --virtualize              Enable virtualization
  --junk                    Add junk code
  --encrypt                 Encrypt obfuscated code
  --iat                     Enable IAT obfuscation
  --random-section          Use random PE section
  --keep-original           Keep original code (don't remove it)
  --AntiDebug               Inserts anti-debugging capabilities and terminates the protected binary if a debugger is detected.
  --Troll                   Crashes the entire OS if a debugger is detected (requires --AntiDebug).
  --AntiDump                Inserts anti-dump mechanisms that break the binary in memory, making dumps harder to analyze.
  --MemoryProtection        Protects obfuscated code against in-memory or on-disk patching.
  --HVPass                  Protect some parts of Ryujin using Microsoft Hypervisor APIs
  --procs <comma,separated,names>  Procedures to obfuscate (default: main, invoke_main, ...)

  --help                    Show this help message

In Action Usage Example:
    RyujinConsole.exe --input C:\\Users\\Keowu\\Documents\\GitHub\\Ryujin\\compiled\\release\\DemoObfuscation.exe --pdb C:\\Users\\Keowu\\Documents\\GitHub\\Ryujin\\compiled\\release\\RyujinConsole.pdb --output C:\\Users\\Keowu\\Documents\\GitHub\\Ryujin\\compiled\\release\\DemoObfuscation.ryujin.exe --virtualize --junk --encrypt --AntiDebug --troll --AntiDump --iat --HVPass --procs main,sub,subadd,sum,invoke_main,__scrt_common_main,j___security_init_cookie

)";

}

auto has_flag(const std::unordered_map<std::string, std::string>& args, const std::string& flag) -> bool {

    return args.find(flag) != args.end();
}

auto parse_args(int argc, char* argv[]) -> std::unordered_map<std::string, std::string> {

    std::unordered_map<std::string, std::string> options;
    for (int i = 1; i < argc; ++i) {
    
        std::string key = argv[i];
        if (key.rfind("--", 0) == 0) 
            if (i + 1 < argc && argv[i + 1][0] != '-') options[key] = argv[++i]; else options[key] = "true"; // Flag-only
        
    }

    return options;
}

auto main(int argc, char* argv[]) -> int {

    auto args = parse_args(argc, argv);

    if (has_flag(args, "--help") || argc == 1) {

        print_help();
        
        return 0;
    }

    auto input = args["--input"];
    auto pdb = args["--pdb"];
    auto output = args["--output"];

    if (input.empty() || pdb.empty() || output.empty()) {
        
        std::cerr << "Error: --input, --pdb, and --output are required.\n";
        print_help();
        
        return 0;
    }

    RyujinObfuscatorConfig config;
    config.m_isIgnoreOriginalCodeRemove = has_flag(args, "--keep-original");
    config.m_isJunkCode = has_flag(args, "--junk");
    config.m_isRandomSection = has_flag(args, "--random-section");
    config.m_isVirtualized = has_flag(args, "--virtualize");
    config.m_isIatObfuscation = has_flag(args, "--iat");
    config.m_isEncryptObfuscatedCode = has_flag(args, "--encrypt");
    config.m_isTrollRerversers = has_flag(args, "--troll");
    config.m_isAntiDebug = has_flag(args, "--AntiDebug");
    config.m_isAntiDump = has_flag(args, "--AntiDump");
    config.m_isMemoryProtection = has_flag(args, "--MemoryProtection");
    config.m_isHVPass = has_flag(args, "--HVPass");

    // Registering a new custom pass for invocation via callback
    config.RegisterCallback(RyujinCustomPassDemo);

    if (has_flag(args, "--procs")) {
        auto rawList = args["--procs"];
        size_t start = 0;
        size_t end = 0;
        int index = 0;

        while ((end = rawList.find(',', start)) != std::string::npos && index < MAX_PROCEDURES) {
            auto procName = rawList.substr(start, end - start);
            strncpy_s(config.m_strProceduresToObfuscate.procedures[index], procName.c_str(), MAX_PROCEDURE_NAME_LEN - 1);
            ++index;
            start = end + 1;
        }

        if (index < MAX_PROCEDURES) {
            auto procName = rawList.substr(start);
            strncpy_s(config.m_strProceduresToObfuscate.procedures[index], procName.c_str(), MAX_PROCEDURE_NAME_LEN - 1);
            ++index;
        }

        config.m_strProceduresToObfuscate.procedureCount = index;
    }
    else {
        print_help();
        return 0;
    }

    auto bSuccess = config.RunRyujin(input, pdb, output, config);
    std::printf("Ryujin core returned: %d\n", bSuccess);

    return bSuccess;
}
