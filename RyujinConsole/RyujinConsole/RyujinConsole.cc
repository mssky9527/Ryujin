#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include "RyujinCore.hh"
#include "RyujinCustomPasses.hh"
#include "th3rd/argparse.hh"


auto main(int argc, char* argv[]) -> int {

    argparse::ArgumentParser ryujinargs("RyujinConsole", "1.1");
    ryujinargs.add_description("Ryujin Obfuscator CLI - Bin2Bin");
    ryujinargs.add_epilog(R"(In Action Usage Example:

    Normal Passes:
        RyujinConsole.exe --input DemoObfuscation.exe --pdb DemoObfuscation.pdb --output DemoObfuscation.ryujin.exe --virtualize --junk --encrypt --AntiDebug --troll --AntiDump --iat --HVPass --procs main,sub,subadd,sum,invoke_main,__scrt_common_main,j___security_init_cookie

    With Custom Passes(MBA Example From Ryujin Paper):
        RyujinConsole.exe --input DemoObfuscation.exe --pdb DemoObfuscation.pdb --output DemoObfuscation.ryujin.exe --procs main,sub,subadd,sum,invoke_main,__scrt_common_main,j___security_init_cookie,mba_sub,mba_subadd,mba_sum,mba_f01,mba_f02,mba_f03,mba_f04,mba_f05,mba_f06,mba_f07,mba_f08,mba_f09,mba_f10,mba_f11,mba_f12,mba_f13,mba_f14,mba_f15,mba_f16,mba_f17,mba_f18,mba_f19,mba_f20,mba_f21,mba_f22,mba_f23,mba_f24,mba_f25,mba_f26,mba_f27,mba_f28,mba_f29,mba_f30,mba_f31,mba_f32,mba_f33,mba_f34,mba_f35,mba_f36,mba_f37,mba_f38,mba_f39,mba_f40,mba_f41,mba_f42,mba_f43,mba_f44,mba_f45,mba_f46,mba_f47,mba_f48,mba_f49,mba_f50,mba_f51,mba_f52,mba_f53,mba_f54,mba_f55,mba_f56,mba_f57,mba_f58,mba_f59,mba_f60,mba_f61,mba_f62,mba_f63,mba_f64,mba_f65,mba_f66,mba_f67,mba_f68,mba_f69,mba_f70,mba_f71,mba_f72,mba_f73,mba_f74,mba_f75,mba_f76,mba_f77,mba_f78,mba_f79,mba_f80,mba_f81,mba_f82,mba_f83,mba_f84,mba_f85,mba_f86,mba_f87,mba_f88,mba_f89,mba_f90,mba_f91,mba_f92,mba_f93,mba_f94,mba_f95,mba_f96,mba_f97,mba_f98,mba_f99,mba_f100

    )");

    // Mandatory arguments
    ryujinargs.add_argument("--input").required().help("Input binary to obfuscate");
    ryujinargs.add_argument("--pdb").required().help("Path to the PDB file");
    ryujinargs.add_argument("--output").required().help("Output path for obfuscated binary");

    // Obfuscation configs customized args
    ryujinargs.add_argument("--virtualize").help("Enable virtualization").default_value(false).implicit_value(true);
    ryujinargs.add_argument("--junk").help("Add junk code").default_value(false).implicit_value(true);
    ryujinargs.add_argument("--encrypt").help("Encrypt obfuscated code").default_value(false).implicit_value(true);
    ryujinargs.add_argument("--iat").help("Enable IAT obfuscation").default_value(false).implicit_value(true);
    ryujinargs.add_argument("--random-section").help("Use random PE section").default_value(false).implicit_value(true);
    ryujinargs.add_argument("--keep-original").help("Keep original code (don't remove it)").default_value(false).implicit_value(true);
    ryujinargs.add_argument("--AntiDebug").help("Inserts anti-debugging capabilities and terminates the protected binary if a debugger is detected").default_value(false).implicit_value(true);
    ryujinargs.add_argument("--troll").help("Crashes the entire OS if a debugger is detected (requires --AntiDebug)").default_value(false).implicit_value(true);
    ryujinargs.add_argument("--AntiDump").help("Inserts anti-dump mechanisms that break the binary in memory, making dumps harder to analyze").default_value(false).implicit_value(true);
    ryujinargs.add_argument("--MemoryProtection").help("Protects obfuscated code against in-memory or on-disk patching").default_value(false).implicit_value(true);
    ryujinargs.add_argument("--HVPass").help("Protect some parts of Ryujin using Microsoft Hypervisor APIs").default_value(false).implicit_value(true);
    ryujinargs.add_argument("--MutateMiniVM").help("Perform the mutation and add full junk code to the Ryujin MiniVM stub, regardless of whether it’s the normal version or the HV pass").default_value(false).implicit_value(true);
    ryujinargs.add_argument("--procs").help("Procedures to obfuscate (comma-separated, e.g., main,invoke_main,...)").default_value(std::string(""));

    // Parse arguments for obfuscation
    try {

        ryujinargs.parse_args(argc, argv);
    
    } catch (const std::exception& err) {
     
        std::cout << "Error when parsing arguments: " << err.what() << "\n\n";
        std::cout << ryujinargs << "\n";
        
        return 0;
    }

    // Extracting mandatory arguments
    auto input = ryujinargs.get<std::string>("--input");
    auto pdb = ryujinargs.get<std::string>("--pdb");
    auto output = ryujinargs.get<std::string>("--output");

    // Configure RyujinObfuscatorConfig
    RyujinObfuscatorConfig config;
    config.m_isIgnoreOriginalCodeRemove = ryujinargs.get<bool>("--keep-original");
    config.m_isJunkCode = ryujinargs.get<bool>("--junk");
    config.m_isRandomSection = ryujinargs.get<bool>("--random-section");
    config.m_isVirtualized = ryujinargs.get<bool>("--virtualize");
    config.m_isIatObfuscation = ryujinargs.get<bool>("--iat");
    config.m_isEncryptObfuscatedCode = ryujinargs.get<bool>("--encrypt");
    config.m_isTrollRerversers = ryujinargs.get<bool>("--troll");
    config.m_isAntiDebug = ryujinargs.get<bool>("--AntiDebug");
    config.m_isAntiDump = ryujinargs.get<bool>("--AntiDump");
    config.m_isMemoryProtection = ryujinargs.get<bool>("--MemoryProtection");
    config.m_isHVPass = ryujinargs.get<bool>("--HVPass");
    config.m_isMutateMiniVM = ryujinargs.get<bool>("--MutateMiniVM");

    // Register custom passes for Ryujin
    config.RegisterCallback(RyujinCustomPasses::RyujinCustomPassDemo);
    config.RegisterCallback(RyujinCustomPasses::RyujinMBAObfuscationPass);

    // Parsing candidates procedures for obfuscation
    auto procsArg = ryujinargs.get<std::string>("--procs");
    if (!procsArg.empty()) {

        size_t start = 0;
        size_t end = 0;
        int index = 0;

        while ((end = procsArg.find(',', start)) != std::string::npos && index < MAX_PROCEDURES) {
        
            auto procName = procsArg.substr(start, end - start);
            strncpy_s(config.m_strProceduresToObfuscate.procedures[index], procName.c_str(), MAX_PROCEDURE_NAME_LEN - 1);
            ++index;
            start = end + 1;
        
        }

        if (index < MAX_PROCEDURES) {
        
            auto procName = procsArg.substr(start);
            strncpy_s(config.m_strProceduresToObfuscate.procedures[index], procName.c_str(), MAX_PROCEDURE_NAME_LEN - 1);
            ++index;
        
        }

        config.m_strProceduresToObfuscate.procedureCount = index;
    }
    else {

        std::cout << "Error: --procs is required.\n\n";
        std::cout << ryujinargs << "\n";
        
        return 0;
    }

    // Run obfuscator
    auto bSuccess = config.RunRyujin(input, pdb, output, config);
    std::printf("Ryujin core returned: %d\n", bSuccess);

    return bSuccess;
}
