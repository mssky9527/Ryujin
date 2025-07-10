#ifdef RYUJINCORE_EXPORTS
#define RYUJINCORE_API __declspec(dllexport)
#else
#define RYUJINCORE_API __declspec(dllimport)
#endif
#include "Ryujin/Ryujin.hh"

RYUJINCORE_API BOOL __stdcall RunRyujinCore(const char* strInputFilePath, const char* strPdbFilePath, const char* strOutputFilePath, RyujinObfuscatorConfig &config);
