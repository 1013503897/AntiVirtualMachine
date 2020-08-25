#include <windows.h>
#include <iostream>
#include <string>
#include <cstdlib>
#include <nb30.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <conio.h>
#include "atlstr.h"
#include "atlbase.h"
#include <tlhelp32.h>
#include <shlwapi.h>

using namespace std;

#pragma comment(lib,"Netapi32.lib")
#pragma comment(lib, "wbemuuid.lib")

typedef struct _ASTAT_ {
	ADAPTER_STATUS adapt;
	NAME_BUFFER NameBuff[30];
} ASTAT, * PASTAT;

//获取MAC地址
extern void getMacAddr(string& strMac);

//通过WMI获取主机信息
extern BOOL ManageWMIInfo(string& result, string table, wstring wcol);

BOOL CheckVMWare1();
BOOL CheckVMWare2();
BOOL CheckVMWare3();
BOOL CheckVMWare4();
BOOL CheckVMWare5();
BOOL CheckVMWare6();
BOOL CheckVMWare7();

BOOL(*fun_array[]) () = { CheckVMWare1, CheckVMWare2, CheckVMWare3, \
	CheckVMWare3, CheckVMWare4,CheckVMWare5,CheckVMWare6,CheckVMWare7 };