#include "AntiVirtualMachine.h"

//��ȡ��ǰ������һ��������MAC��ַ
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

//ͨ��WMI��ȡ������Ϣ
BOOL ManageWMIInfo(string& result, string table, wstring wcol)
{
	HRESULT hres;
	char bord[1024];
	//��ʼ��COM 
	hres = CoInitialize(0);
	//���WMI����COM�ӿ�  
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
	//ͨ�����ӽӿ�����WMI���ں˶�����ROOT//CIMV2  
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
	//�����������İ�ȫ����   
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
	//ͨ�������������WMI��������
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
			<< " Error code = 0x��"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return false;
	}
	//ѭ��ö�����еĽ������
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
	//�ͷ���Դ  
	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	pclsObj->Release();
	CoUninitialize();
	return true;
}

//1.��ѯI/Oͨ�Ŷ˿�
BOOL CheckVMWare1(){
	BOOL bResult = TRUE;
	__try{
		__asm{
			push   edx
			push   ecx
			push   ebx				//���滷��
			mov    eax, 'VMXh'
			mov    ebx, 0			//��ebx����
			mov    ecx, 10			//ָ�����ܺţ����ڻ�ȡVMWare�汾��Ϊ0x14ʱ��ȡVM�ڴ��С
			mov    edx, 'VX'		//�˿ں�
			in     eax, dx			//�Ӷ˿�edx ��ȡVMware��eax
			cmp    ebx, 'VMXh'		//�ж�ebx���Ƿ����VMware�汾��VMXh�������������������
			setz[bResult]			//���÷���ֵ
			pop    ebx				//�ָ�����
			pop    ecx
			pop    edx
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)	//���δ����VMware�У��򴥷����쳣
	{
		bResult = FALSE;
	}
	return bResult;
}

//2.ͨ��MAC��ַ���
BOOL CheckVMWare2() {
	string strMac;
	getMacAddr(strMac);
	if (strMac == "00-05-69" || strMac == "00-0c-29" || strMac == "00-50-56")
		return TRUE;
	return FALSE;
}

//3.CPUID���
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
		and ecx, 0x80000000;//ȡ���λ
		test ecx, ecx;		//���ecx�Ƿ�Ϊ0
		setz[b_IsVM];		//Ϊ�� (ZF=1) ʱ�����ֽ�
		popfd;
		popad;
	}
	if (b_IsVM)
		return FALSE;
	return TRUE;
}

//4.ͨ���������кš��ͺš�ϵͳ�����ڴ������Ƶ�����Ӳ����Ϣ
BOOL CheckVMWare4() {
	string table = "Win32_DiskDrive";
	wstring wcol = L"Caption";
	string ret;
	ManageWMIInfo(ret, table, wcol);
	if (ret.find("VMware") != string::npos)
		return TRUE;
	return FALSE;
}

//5.�����ض����̼��
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

//6.ͨ��ע�����
BOOL CheckVMWare6() {
	HKEY hkey;
	if (RegOpenKey(HKEY_CLASSES_ROOT, L"\\Applications\\VMwareHostOpen.exe", &hkey) == ERROR_SUCCESS)
		return TRUE;
	return FALSE;
}

//7.�ļ�·�����
BOOL CheckVMWare7() {
	if (PathIsDirectory(L"C:\\Program Files\\VMware\\") == 0)
		return FALSE;
	return TRUE;
}

int main(){
	for (auto check_func : check_func_array) {
		if (check_func())
			printf("�����:true\r\n");
		else
			printf("�����:false\r\n");
	}
	system("pause");
}
