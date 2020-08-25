#include "AntiVirtualMachine.h"

//获取当前主机第一张网卡的MAC地址
void getMacAddr(string& mac){
	NCB Ncb;
	ASTAT Adapter;
	UCHAR uRetCode;
	LANA_ENUM lenum;
	memset(&Ncb, 0, sizeof(Ncb));
	Ncb.ncb_command = NCBENUM;
	Ncb.ncb_buffer = (UCHAR*)&lenum;
	Ncb.ncb_length = sizeof(lenum);
	uRetCode = Netbios(&Ncb);
	for (int i = 0; i < lenum.length; i++) {
		memset(&Ncb, 0, sizeof(Ncb));
		Ncb.ncb_command = NCBRESET;
		Ncb.ncb_lana_num = lenum.lana[i];
		uRetCode = Netbios(&Ncb);
		memset(&Ncb, 0, sizeof(Ncb));
		Ncb.ncb_command = NCBASTAT;
		Ncb.ncb_lana_num = lenum.lana[i];
		strcpy((char*)Ncb.ncb_callname, "*");
		Ncb.ncb_buffer = (unsigned char*)&Adapter;
		Ncb.ncb_length = sizeof(Adapter);
		uRetCode = Netbios(&Ncb);
		if (uRetCode == 0) {
			char tmp[128];
			sprintf(tmp, "%02x-%02x-%02x",
				Adapter.adapt.adapter_address[0],
				Adapter.adapt.adapter_address[1],
				Adapter.adapt.adapter_address[2]
			);
			mac = tmp;
		}
	}
}

//通过WMI获取主机信息
BOOL ManageWMIInfo(string& result, string table, wstring wcol)
{
	HRESULT hres;
	char bord[1024];
	//初始化COM 
	hres = CoInitialize(0);
	//获得WMI连接COM接口  
	IWbemLocator* pLoc = NULL;
	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)&pLoc);
	if (FAILED(hres)) {
		cout << "Failed to create IWbemLocator object."
			<< "Err code = 0x"
			<< hex << hres << endl;
		CoUninitialize();
		return false;
	}
	//通过连接接口连接WMI的内核对象名ROOT//CIMV2  
	IWbemServices* pSvc = NULL;
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
		NULL, // User name. NULL = current user
		NULL, // User password. NULL = current
		0, // Locale. NULL indicates current
		NULL, // Security flags.
		0, // Authority (e.g. Kerberos)
		0, // Context object 
		&pSvc // pointer to IWbemServices proxy
	);
	if (FAILED(hres)) {
		cout << "Could not connect. Error code = 0x"
			<< hex << hres << endl;
		pLoc->Release();
		CoUninitialize();
		return false;
	}
	//设置请求代理的安全级别   
	hres = CoSetProxyBlanket(
		pSvc, // Indicates the proxy to set
		RPC_C_AUTHN_WINNT, // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_NONE, // RPC_C_AUTHZ_xxx
		NULL, // Server principal name 
		RPC_C_AUTHN_LEVEL_CALL, // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
		NULL, // client identity
		EOAC_NONE // proxy capabilities 
	);
	if (FAILED(hres)) {
		cout << "Could not set proxy blanket. Error code = 0x"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return false;
	}
	//通过请求代理来向WMI发送请求
	IEnumWbemClassObject* pEnumerator = NULL;
	string select = "SELECT * FROM " + table;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t(select.c_str()),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);
	if (FAILED(hres)) {
		cout << "Query for Network Adapter Configuration failed."
			<< " Error code = 0x”"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return false;
	}
	//循环枚举所有的结果对象
	ULONG uReturn = 0;
	IWbemClassObject* pclsObj = nullptr;
	while (pEnumerator) {
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);
		if (0 == uReturn)
			break;
		VARIANT vtProp;
		VariantInit(&vtProp);
		hr = pclsObj->Get(wcol.c_str(), 0, &vtProp, 0, 0);
		if (!FAILED(hr)) {
			CW2A tmpstr1(vtProp.bstrVal);
			strcpy_s(bord, 200, tmpstr1);
			result = bord;
		}
		VariantClear(&vtProp);
	}
	//释放资源  
	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	pclsObj->Release();
	CoUninitialize();
	return true;
}

//1.查询I/O通信端口
BOOL CheckVMWare1(){
	BOOL bResult = TRUE;
	__try{
		__asm{
			push   edx
			push   ecx
			push   ebx				//保存环境
			mov    eax, 'VMXh'
			mov    ebx, 0			//将ebx清零
			mov    ecx, 10			//指定功能号，用于获取VMWare版本，为0x14时获取VM内存大小
			mov    edx, 'VX'		//端口号
			in     eax, dx			//从端口edx 读取VMware到eax
			cmp    ebx, 'VMXh'		//判断ebx中是否包含VMware版本’VMXh’，若是则在虚拟机中
			setz[bResult]			//设置返回值
			pop    ebx				//恢复环境
			pop    ecx
			pop    edx
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)	//如果未处于VMware中，则触发此异常
	{
		bResult = FALSE;
	}
	return bResult;
}

//2.通过MAC地址检测
BOOL CheckVMWare2() {
	string strMac;
	getMacAddr(strMac);
	if (strMac == "00-05-69" || strMac == "00-0c-29" || strMac == "00-50-56")
		return TRUE;
	return FALSE;
}

//3.CPUID检测
BOOL CheckVMWare3() {
	DWORD dwECX = 0;
	bool b_IsVM = true;
	_asm
	{
		pushad;
		pushfd;
		mov eax, 1;
		cpuid;
		mov dwECX, ecx;
		and ecx, 0x80000000;//取最高位
		test ecx, ecx;		//检测ecx是否为0
		setz[b_IsVM];		//为零 (ZF=1) 时设置字节
		popfd;
		popad;
	}
	if (b_IsVM)
		return FALSE;
	return TRUE;
}

//4.通过主板序列号、型号、系统盘所在磁盘名称等其他硬件信息
BOOL CheckVMWare4() {
	string table = "Win32_DiskDrive";
	wstring wcol = L"Caption";
	string ret;
	ManageWMIInfo(ret, table, wcol);
	if (ret.find("VMware") != string::npos)
		return TRUE;
	return FALSE;
}

//5.搜索特定进程检测
BOOL CheckVMWare5() {
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return FALSE;
	BOOL bMore = Process32First(hProcessSnap, &pe32);
	while (bMore) {
		if (!wcscmp(pe32.szExeFile, L"vmtoolsd.exe"))
			return TRUE;
		bMore = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
	return FALSE;
}

//6.通过注册表检测
BOOL CheckVMWare6() {
	HKEY hkey;
	if (RegOpenKey(HKEY_CLASSES_ROOT, L"\\Applications\\VMwareHostOpen.exe", &hkey) == ERROR_SUCCESS)
		return TRUE;
	return FALSE;
}

//7.文件路径检测
BOOL CheckVMWare7() {
	if (PathIsDirectory(L"C:\\Program Files\\VMware\\") == 0)
		return FALSE;
	return TRUE;
}

int main(){
	for (auto check_func : check_func_array) {
		if (check_func())
			printf("检测结果:true\r\n");
		else
			printf("检测结果:false\r\n");
	}
	system("pause");
}
