#include "RyujinCore.hh"

/*
    Disable all optimizations before compile for release - MSVC sucks - Build ryujincore in debug or use contexpr mainly on fix relocs
*/

RYUJINCORE_API BOOL __stdcall RunRyujinCore(const char* strInputFilePath, const char* strPdbFilePath, const char* strOutputFilePath, RyujinObfuscatorConfig& config) {

    if (!strInputFilePath || !strPdbFilePath || !strOutputFilePath) return FALSE;

    if (config.m_strdProceduresToObfuscate.empty()) {

        std::vector<std::string> strProcsProcessed;

        strProcsProcessed.reserve(config.m_strProceduresToObfuscate.procedureCount);

        for (int i = 0; i < config.m_strProceduresToObfuscate.procedureCount; ++i)
            strProcsProcessed.emplace_back(config.m_strProceduresToObfuscate.procedures[i]);

        config.m_strdProceduresToObfuscate.assign(strProcsProcessed.begin(), strProcsProcessed.end());

    }

    std::unique_ptr<Ryujin> ryujin = std::make_unique<Ryujin>(strInputFilePath, strPdbFilePath, strOutputFilePath);

    ryujin.get()->listRyujinProcedures();

    ryujin.get()->run(config);

    ryujin.reset();

    return TRUE;
}
