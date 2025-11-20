#include <windows.h>
#include <iostream>
#include <cstdio>
#include <string>
#include <cstdint>

// Test MBA with: RyujinConsole.exe --input DemoObfuscation.exe --pdb DemoObfuscation.pdb --output DemoObfuscation.ryujin.exe --procs main,sub,subadd,sum,invoke_main,__scrt_common_main,j___security_init_cookie,mba_sub,mba_subadd,mba_sum,mba_f01,mba_f02,mba_f03,mba_f04,mba_f05,mba_f06,mba_f07,mba_f08,mba_f09,mba_f10,mba_f11,mba_f12,mba_f13,mba_f14,mba_f15,mba_f16,mba_f17,mba_f18,mba_f19,mba_f20,mba_f21,mba_f22,mba_f23,mba_f24,mba_f25,mba_f26,mba_f27,mba_f28,mba_f29,mba_f30,mba_f31,mba_f32,mba_f33,mba_f34,mba_f35,mba_f36,mba_f37,mba_f38,mba_f39,mba_f40,mba_f41,mba_f42,mba_f43,mba_f44,mba_f45,mba_f46,mba_f47,mba_f48,mba_f49,mba_f50,mba_f51,mba_f52,mba_f53,mba_f54,mba_f55,mba_f56,mba_f57,mba_f58,mba_f59,mba_f60,mba_f61,mba_f62,mba_f63,mba_f64,mba_f65,mba_f66,mba_f67,mba_f68,mba_f69,mba_f70,mba_f71,mba_f72,mba_f73,mba_f74,mba_f75,mba_f76,mba_f77,mba_f78,mba_f79,mba_f80,mba_f81,mba_f82,mba_f83,mba_f84,mba_f85,mba_f86,mba_f87,mba_f88,mba_f89,mba_f90,mba_f91,mba_f92,mba_f93,mba_f94,mba_f95,mba_f96,mba_f97,mba_f98,mba_f99,mba_f100
static uint32_t mba_f01(uint32_t x) { return x + 0x9E3779B1u; }
static uint32_t mba_f02(uint32_t x) { return x - 0x3C6EF372u; }
static uint32_t mba_f03(uint32_t x) { return x * 1664525u; }
static uint32_t mba_f04(uint32_t x) { return x / 3u; }
static uint32_t mba_f05(uint32_t x) { return x + 0x7F4A7C15u; }
static uint32_t mba_f06(uint32_t x) { return x - 0x1234567u; }
static uint32_t mba_f07(uint32_t x) { return x * 1103515245u; }
static uint32_t mba_f08(uint32_t x) { return x / 5u; }
static uint32_t mba_f09(uint32_t x) { return x + 0xA5A5A5A5u; }
static uint32_t mba_f10(uint32_t x) { return x - 0x5A5A5A5Au; }

static uint32_t mba_f11(uint32_t x) { return x * 742938285u; }
static uint32_t mba_f12(uint32_t x) { return x / 7u; }
static uint32_t mba_f13(uint32_t x) { return x + 0xCAFEBABEu; }
static uint32_t mba_f14(uint32_t x) { return x - 27182818u; }
static uint32_t mba_f15(uint32_t x) { return x * 2654435761u; }
static uint32_t mba_f16(uint32_t x) { return x / 11u; }
static uint32_t mba_f17(uint32_t x) { return x + 0x0F0F0F0Fu; }
static uint32_t mba_f18(uint32_t x) { return x - 0xF0F0F0F0u; }
static uint32_t mba_f19(uint32_t x) { return x * 99999989u; }
static uint32_t mba_f20(uint32_t x) { return x / 13u; }

static uint32_t mba_f21(uint32_t x) { return x + 42424242u; }
static uint32_t mba_f22(uint32_t x) { return x - 12398712u; }
static uint32_t mba_f23(uint32_t x) { return x * 429496729u; }
static uint32_t mba_f24(uint32_t x) { return x / 17u; }
static uint32_t mba_f25(uint32_t x) { return x + 0x55555555u; }
static uint32_t mba_f26(uint32_t x) { return x - 0x33333333u; }
static uint32_t mba_f27(uint32_t x) { return x * 314159265u; }
static uint32_t mba_f28(uint32_t x) { return x / 19u; }
static uint32_t mba_f29(uint32_t x) { return x + 0xDEADBEEFu; }
static uint32_t mba_f30(uint32_t x) { return x - 0x0BADF00Du; }

static uint32_t mba_f31(uint32_t x) { return x * 123456791u; }
static uint32_t mba_f32(uint32_t x) { return x / 23u; }
static uint32_t mba_f33(uint32_t x) { return x + 0x89ABCDEFu; }
static uint32_t mba_f34(uint32_t x) { return x - 0x76543210u; }
static uint32_t mba_f35(uint32_t x) { return x * 20201227u; }
static uint32_t mba_f36(uint32_t x) { return x / 29u; }
static uint32_t mba_f37(uint32_t x) { return x + 0x11111111u; }
static uint32_t mba_f38(uint32_t x) { return x - 0x22222222u; }
static uint32_t mba_f39(uint32_t x) { return x * 400000003u; }
static uint32_t mba_f40(uint32_t x) { return x / 31u; }

static uint32_t mba_f41(uint32_t x) { return x + 98765432u; }
static uint32_t mba_f42(uint32_t x) { return x - 19283746u; }
static uint32_t mba_f43(uint32_t x) { return x * 31415927u; }
static uint32_t mba_f44(uint32_t x) { return x / 37u; }
static uint32_t mba_f45(uint32_t x) { return x + 0xABCDEF01u; }
static uint32_t mba_f46(uint32_t x) { return x - 0x10234567u; }
static uint32_t mba_f47(uint32_t x) { return x * 27182818u; }
static uint32_t mba_f48(uint32_t x) { return x / 41u; }
static uint32_t mba_f49(uint32_t x) { return x + 0x13579BDFu; }
static uint32_t mba_f50(uint32_t x) { return x - 0x2468ACE0u; }

static uint32_t mba_f51(uint32_t x) { return x * 100000007u; }
static uint32_t mba_f52(uint32_t x) { return x / 43u; }
static uint32_t mba_f53(uint32_t x) { return x + 0x0C0C0C0Cu; }
static uint32_t mba_f54(uint32_t x) { return x - 0xC0C0C0C0u; }
static uint32_t mba_f55(uint32_t x) { return x * 98765431u; }
static uint32_t mba_f56(uint32_t x) { return x / 47u; }
static uint32_t mba_f57(uint32_t x) { return x + 0xFEEDFACEu; }
static uint32_t mba_f58(uint32_t x) { return x - 0xCAFED00Du; }
static uint32_t mba_f59(uint32_t x) { return x * 20230503u; }
static uint32_t mba_f60(uint32_t x) { return x / 53u; }

static uint32_t mba_f61(uint32_t x) { x = x + 0xA1B2C3D4u; x = x * 1664525u; return x / 3u; }
static uint32_t mba_f62(uint32_t x) { x = x - 0x0F1E2D3Cu; x = x * 1103515245u; return x / 5u; }
static uint32_t mba_f63(uint32_t x) { x = x + 0x01020304u; x = x - 0x04030201u; return x * 3u; }
static uint32_t mba_f64(uint32_t x) { x = x * 7u; x = x + 0x42424242u; return x / 9u; }
static uint32_t mba_f65(uint32_t x) { x = x + 0xCAFED00Du; x = x - 0xDEADBEEFu; return x * 13u; }
static uint32_t mba_f66(uint32_t x) { x = (x / 2u) + 0x33333333u; return x * 5u; }
static uint32_t mba_f67(uint32_t x) { x = x * 3u; x = x + 77777777u; return x / 11u; }
static uint32_t mba_f68(uint32_t x) { x = x + 0x89ABCDEFu; x = x - 0x11111111u; return x * 17u; }
static uint32_t mba_f69(uint32_t x) { x = x * 19u; x = x + 0x55555555u; return x / 21u; }
static uint32_t mba_f70(uint32_t x) { x = x + 31415926u; x = x * 23u; return x - 27182818u; }

static uint32_t mba_f71(uint32_t x) { x = x * 29u; x = x + 24681012u; return x / 7u; }
static uint32_t mba_f72(uint32_t x) { x = x + 0x33344455u; x = x * 31u; return x - 12345678u; }
static uint32_t mba_f73(uint32_t x) { x = x / 3u; x = x + 0xABCDEFFFu; return x * 37u; }
static uint32_t mba_f74(uint32_t x) { x = x - 4242424u; x = x * 41u; return x + 0x01010101u; }
static uint32_t mba_f75(uint32_t x) { x = x + 0xBBCCDDEEu; x = x / 5u; return x * 43u; }
static uint32_t mba_f76(uint32_t x) { x = x * 47u; x = x - 0x11122233u; return x + 99999999u; }
static uint32_t mba_f77(uint32_t x) { x = x + 0x2468ACE0u; x = x * 53u; return x / 13u; }
static uint32_t mba_f78(uint32_t x) { x = x * 59u; x = x - 0x0BADBEEFu; return x + 20242024u; }
static uint32_t mba_f79(uint32_t x) { x = x + 0x87654321u; x = x / 17u; return x * 61u; }
static uint32_t mba_f80(uint32_t x) { x = x * 67u; x = x + 0x13572468u; return x / 19u; }

static uint32_t mba_f81(uint32_t x) { return x + 0x0DEADBEEu; }
static uint32_t mba_f82(uint32_t x) { return x - 0x00BEEF00u; }
static uint32_t mba_f83(uint32_t x) { x = x * 83u; x = x + 0x89; return x / 3u; }
static uint32_t mba_f84(uint32_t x) { x = (x >> 3) + 0x4242u; return x * 7u; }
static uint32_t mba_f85(uint32_t x) { return x ^ 0xAAAAAAAAu; }
static uint32_t mba_f86(uint32_t x) { x = x + 1234567u; return x * 13u; }
static uint32_t mba_f87(uint32_t x) { return x - 3141592u; }
static uint32_t mba_f88(uint32_t x) { return x * 97u; }
static uint32_t mba_f89(uint32_t x) { return x / 2u; }
static uint32_t mba_f90(uint32_t x) { return x + 0x13579u; }

static uint32_t mba_f91(uint32_t x) { return x - 0x24680u; }
static uint32_t mba_f92(uint32_t x) { return (x * 3u) + (x >> 5); }
static uint32_t mba_f93(uint32_t x) { return x ^ (x << 7); }
static uint32_t mba_f94(uint32_t x) { return (x / 3u) ^ 0x55AA55AAu; }
static uint32_t mba_f95(uint32_t x) { return x + 0xFEEDu; }
static uint32_t mba_f96(uint32_t x) { return x * 101u; }
static uint32_t mba_f97(uint32_t x) { return x / 19u; }
static uint32_t mba_f98(uint32_t x) { return x + 0xBEEFu; }
static uint32_t mba_f99(uint32_t x) { x = x * 3u; x = x + 0xABCu; return x / 5u; }
static uint32_t mba_f100(uint32_t x) { return x ^ 0xFFFFFFFFu; }

uint32_t mba_encrypt32(uint32_t v, uint32_t key) {

    uint32_t x = v ^ (key + 0x9E3779B9u);

    x = mba_f03(x);
    x = mba_f17(x + (key ^ 0xAAAAAAAAu));
    x = mba_f61(x);
    x = mba_f09(x - (key * 3u));
    x = mba_f24(x ^ key);
    x = mba_f47(x + 0x7C6EF372u);
    x = mba_f12(x ^ (key >> 3));
    x = mba_f55(x + (key * 5u));
    x = mba_f28(x);
    x = mba_f70(x ^ (key * 7u));
    x = mba_f33(x + 0x33333333u);
    x = mba_f02(x - (key + 0x13579BDFu));
    x = mba_f76(x);
    x = mba_f40(x ^ (key - 0x22222222u));
    x = mba_f19(x + (key >> 7));
    x = mba_f45(x);
    x = mba_f68(x - (key * 11u));
    x = mba_f14(x);

    x = mba_f83(x);
    x = mba_f86(x);
    x = mba_f61(x ^ (key + 0x0F0F0F0Fu));
    x = mba_f04(x + 13u);
    x = mba_f31(x ^ (key * 13u));
    x = mba_f22(x);
    x = mba_f50(x ^ (key + 0xDEADBEEFu));
    x = mba_f07(x + 0xCAFEBABE);
    x = mba_f11(x ^ (key >> 5));
    x = mba_f66(x - (key * 17u));
    x = mba_f39(x);
    x = mba_f56(x + (key ^ 0x55555555u));
    x = mba_f73(x);
    x = mba_f29(x - (key << 2));
    x = mba_f18(x);
    x = mba_f26(x ^ (key * 19u));
    x = mba_f44(x + 0xFEEDFACEu);
    x = mba_f32(x);
    x = mba_f60(x ^ (key + 0xCAFED00Du));
    x = mba_f49(x - (key >> 2));
    x = mba_f38(x);
    x = mba_f59(x + (key * 23u));
    x = mba_f35(x);
    x = mba_f75(x ^ (key - 0x0C0C0C0Cu));
    x = mba_f08(x);
    x = mba_f71(x + (key | 0x01010101u));
    x = mba_f20(x);
    x = mba_f54(x ^ (key & 0xFFFFFFFFu));
    x = mba_f43(x + 42424242u);
    x = mba_f46(x);
    x = mba_f48(x ^ (key * 29u));
    x = mba_f10(x);
    x = mba_f27(x + (key ^ 0x89ABCDEFu));
    x = mba_f41(x);
    x = mba_f65(x - (key * 31u));
    x = mba_f72(x);
    x = mba_f37(x + (key >> 11));
    x = mba_f34(x ^ 0x10234567u);
    x = mba_f30(x);
    x = mba_f53(x + (key * 37u));
    x = mba_f64(x);
    x = mba_f57(x ^ (key - 0x2468ACE0u));

    x = mba_f85(x);
    x = mba_f99(x);
    x = mba_f81(x);
    x = mba_f82(x);
    x = mba_f84(x);
    x = mba_f88(x);
    x = mba_f90(x);
    x = mba_f92(x);
    x = mba_f93(x);

    x = x + 0xA5A5A5A5u + (key ^ 0x5A5A5A5Au);
    x = x * 1664525u;
    x = x / 3u;

    return x;
}

// Normal - Non MBA
uint32_t sum(uint32_t n20) {

    return n20 + 10;
}

uint32_t sub(uint32_t n10) {

    return 20 - n10;
}

uint32_t subadd(uint32_t n400) {

    return n400 + 8;
}

// RyujinConsole.exe --input DemoObfuscation.exe --pdb DemoObfuscation.pdb --output DemoObfuscation.ryujin.exe --iat --procs main,mba_sub,mba_subadd,mba_sum,invoke_main,__scrt_common_main,j___security_init_cookie
int main(int argc, const char** argv, const char** envp) {

    std::printf("Hello World!\n");
    std::printf("Hello World..\n");
    std::printf("Xdxd..\n");

    auto v3 = sum(20);
    std::printf("%x\n", v3);

    auto v4 = sub(10);

    auto v5 = subadd(400);
    std::printf("%x\n", v5);

    char username[256]{ 0 };
    DWORD username_len = sizeof(username);
    if (::GetUserNameA(_Out_ username, _In_ &username_len))
        std::printf("Username: %s\n", username);

    SYSTEMTIME st;
    ::GetSystemTime(_Out_ &st);
    std::printf("Current system time: %02u:%02u:%02u\n",
        static_cast<unsigned>(st.wHour),
        static_cast<unsigned>(st.wMinute),
        static_cast<unsigned>(st.wSecond));

    char computerName[256] = { 0 };
    DWORD comp_len = sizeof(computerName);
    if (::GetComputerNameA(_Out_ computerName, _In_ &comp_len))
        std::printf("Computer Name: %s\n", computerName);

    ::MessageBoxA(_In_ nullptr, _In_ "Ola mundo...", _In_ "Ola Mundo...", _In_ MB_ICONINFORMATION);
    ::Beep(_In_ 750, _In_ 300);

    auto plain = 0x12345678u;
    auto key = 0xDEADBEEFu;
    auto enc = mba_encrypt32(plain, key);
    std::printf("plain=0x%08X key=0x%08X enc=0x%08X\n", plain, key, enc);

    std::cin.get();

    return 0;
}
