#include "RyujinCore.hh"

RYUJINCORE_API BOOL __stdcall RunRyujinCore(const std::string& strInputFilePath, const std::string& strPdbFilePath, const std::string& strOutputFilePath, RyujinObfuscatorConfig& config) {

    std::unique_ptr<Ryujin> ryujin = std::make_unique<Ryujin>(strInputFilePath, strPdbFilePath, strOutputFilePath);

    ryujin.get()->listRyujinProcedures();

    ryujin.get()->run(config);

    ryujin.reset();

    return TRUE;
}
