#include <iostream>

// TODO: Fit it in a new class for ryujin
#include <vector>
#include <Windows.h>
class RyujinObfuscatorConfig {

public:
    bool m_isRandomSection; // Randomize the name of the new section with the processed code -> ".Ryujin" standard
    bool m_isVirtualized; // Virtualize the code [Try as much as possible]
    bool m_isIatObfuscation; //Process IAT Obfuscation
    bool m_isJunkCode; // Insert junk code to confuse
    bool m_isIgnoreOriginalCodeRemove; // Do not remove the original code after processing (replace the original instructions with NOPs)
    bool m_isEncryptObfuscatedCode; // The user wants to encrypt all obfuscated code to avoid detection
    std::vector<std::string> m_strProceduresToObfuscate; // Names of the procedures to obfuscate

    bool RunRyujin(const std::string& strInputFilePath, const std::string& strPdbFilePath, const std::string& strOutputFilePath, RyujinObfuscatorConfig& config) {

        using tpdRunRyujinCore = BOOL (__stdcall *)(const std::string& strInputFilePath, const std::string& strPdbFilePath, const std::string& strOutputFilePath, RyujinObfuscatorConfig& config);

        auto hModule = LoadLibraryW(L"RyujinCore.dll");

        if (!hModule) return FALSE;

        auto RunRyujinCore = reinterpret_cast<tpdRunRyujinCore>(GetProcAddress(hModule, "?RunRyujinCore@@YAHAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@00AEAVRyujinObfuscatorConfig@@@Z"));

        if (!RunRyujinCore) return FALSE;

        return RunRyujinCore(strInputFilePath, strPdbFilePath, strOutputFilePath, config);
    }

};



auto main() -> int {

    std::cout << "Hello World!\n";

    RyujinObfuscatorConfig config;
    config.m_isIgnoreOriginalCodeRemove = FALSE;
    config.m_isJunkCode = TRUE;
    config.m_isRandomSection = FALSE;
    config.m_isVirtualized = TRUE;
    config.m_isIatObfuscation = TRUE;
    config.m_isEncryptObfuscatedCode = TRUE;
    std::vector<std::string> procsToObfuscate{

        "sum",
        "sub",
        "subadd",
        "main",
        "invoke_main"
        "__scrt_common_main",
        "j___security_init_cookie"
    
    };
    config.m_strProceduresToObfuscate.assign(procsToObfuscate.begin(), procsToObfuscate.end());

    auto bSuccess = config.RunRyujin("C:\\Users\\Keowu\\Documents\\GitHub\\Ryujin\\RyujinConsole\\x64\\Release\\DemoObfuscation.exe", "C:\\Users\\Keowu\\Documents\\GitHub\\Ryujin\\RyujinConsole\\x64\\Release\\DemoObfuscation.pdb", "C:\\Users\\Keowu\\Documents\\GitHub\\Ryujin\\RyujinConsole\\x64\\Release\\DemoObfuscation.obfuscated.exe", config);

    std::printf("Ryujin core returned: %d\n", bSuccess);

    std::cin.get();

    return 0;
}