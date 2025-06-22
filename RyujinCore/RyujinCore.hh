#ifdef RYUJINCORE_EXPORTS
#define RYUJINCORE_API __declspec(dllexport)
#else
#define RYUJINCORE_API __declspec(dllimport)
#endif
#include "Ryujin/Ryujin.hh"

RYUJINCORE_API BOOL __stdcall RunRyujinCore(const std::string& strInputFilePath, const std::string& strPdbFilePath, const std::string& strOutputFilePath, RyujinObfuscatorConfig &config);
