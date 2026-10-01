#define _WIN32_DCOM

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <wbemidl.h>
#include <comdef.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>
#include <iomanip>
#include <ctime>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

using namespace std;

wstring VariantToString(VARIANT& value)
{
    if (value.vt == VT_NULL || value.vt == VT_EMPTY)
        return L"Unknown";

    switch (value.vt)
    {
    case VT_BSTR:
        return value.bstrVal ? value.bstrVal : L"Unknown";

    case VT_I4:
        return to_wstring(value.lVal);

    case VT_UI4:
        return to_wstring(value.ulVal);

    case VT_I8:
        return to_wstring(value.llVal);

    case VT_UI8:
        return to_wstring(value.ullVal);

    case VT_I2:
        return to_wstring(value.iVal);

    case VT_UI2:
        return to_wstring(value.uiVal);

    case VT_BOOL:
        return value.boolVal ? L"True" : L"False";
    }

    VARIANT converted;
    VariantInit(&converted);

    if (SUCCEEDED(
        VariantChangeType(
            &converted,
            &value,
            0,
            VT_BSTR)))
    {
        wstring result = converted.bstrVal;
        VariantClear(&converted);
        return result;
    }

    return L"Unknown";
}

wstring BytesToGB(const wstring& bytes)
{
    try
    {
        unsigned long long value = stoull(bytes);

        double gb =
            static_cast<double>(value) /
            (1024.0 * 1024.0 * 1024.0);

        wstringstream output;

        output << fixed
               << setprecision(2)
               << gb
               << L" GB";

        return output.str();
    }
    catch (...)
    {
        return bytes;
    }
}

void AddWMISection(
    IWbemServices* service,
    wstringstream& report,
    const wstring& label,
    const wstring& query,
    const vector<pair<wstring, wstring>>& properties)
{
    IEnumWbemClassObject* enumerator = nullptr;

    HRESULT result = service->ExecQuery(
        bstr_t("WQL"),
        bstr_t(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY |
        WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &enumerator
    );

    if (FAILED(result))
    {
        report << label << L": Unable to retrieve information.\n\n";
        return;
    }

    IWbemClassObject* object = nullptr;

    ULONG returned = 0;

    int item = 1;

    while (enumerator)
    {
        enumerator->Next(
            WBEM_INFINITE,
            1,
            &object,
            &returned
        );

        if (returned == 0)
            break;

        if (item == 1)
        {
            report << label << L":\n";
        }
        else
        {
            report << label
                   << L" "
                   << item
                   << L":\n";
        }

        for (const auto& property : properties)
        {
            VARIANT value;
            VariantInit(&value);

            object->Get(
                property.second.c_str(),
                0,
                &value,
                nullptr,
                nullptr
            );

            wstring text = VariantToString(value);

            if (property.second == L"Capacity" ||
                property.second == L"Size" ||
                property.second == L"TotalPhysicalMemory")
            {
                text = BytesToGB(text);
            }

            report
                << property.first
                << L": "
                << text
                << L"\n";

            VariantClear(&value);
        }

        report << L"\n";

        object->Release();
        object = nullptr;

        item++;
    }

    enumerator->Release();
}

void AddNetworkInformation(wstringstream& report)
{
    ULONG bufferSize = 15000;

    vector<unsigned char> buffer(bufferSize);

    PIP_ADAPTER_ADDRESSES addresses =
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(
            buffer.data()
        );

    ULONG result = GetAdaptersAddresses(
        AF_UNSPEC,
        GAA_FLAG_INCLUDE_PREFIX,
        nullptr,
        addresses,
        &bufferSize
    );

    if (result == ERROR_BUFFER_OVERFLOW)
    {
        buffer.resize(bufferSize);

        addresses =
            reinterpret_cast<PIP_ADAPTER_ADDRESSES>(
                buffer.data()
            );

        result = GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX,
            nullptr,
            addresses,
            &bufferSize
        );
    }

    if (result != NO_ERROR)
    {
        report << L"Network Adapter: Unable to retrieve information.\n";
        return;
    }

    int adapterNumber = 1;

    for (PIP_ADAPTER_ADDRESSES adapter = addresses;
         adapter != nullptr;
         adapter = adapter->Next)
    {
        if (adapter->OperStatus != IfOperStatusUp)
            continue;

        report
            << L"Network Adapter "
            << adapterNumber
            << L":\n";

        report
            << L"Name: "
            << adapter->FriendlyName
            << L"\n";

        report << L"MAC Address: ";

        if (adapter->PhysicalAddressLength > 0)
        {
            for (ULONG i = 0;
                 i < adapter->PhysicalAddressLength;
                 i++)
            {
                if (i != 0)
                    report << L"-";

                report
                    << uppercase
                    << hex
                    << setw(2)
                    << setfill(L'0')
                    << static_cast<int>(
                        adapter->PhysicalAddress[i]
                    );
            }

            report << dec;
        }
        else
        {
            report << L"Unknown";
        }

        report << L"\n";

        bool foundAddress = false;

        for (PIP_ADAPTER_UNICAST_ADDRESS address =
                 adapter->FirstUnicastAddress;
             address != nullptr;
             address = address->Next)
        {
            wchar_t addressBuffer[INET6_ADDRSTRLEN];

            void* addressPointer = nullptr;

            int family =
                address->Address.lpSockaddr->sa_family;

            if (family == AF_INET)
            {
                sockaddr_in* ipv4 =
                    reinterpret_cast<sockaddr_in*>(
                        address->Address.lpSockaddr
                    );

                addressPointer =
                    &(ipv4->sin_addr);

                InetNtopW(
                    AF_INET,
                    addressPointer,
                    addressBuffer,
                    INET_ADDRSTRLEN
                );

                report
                    << L"IPv4 Address: "
                    << addressBuffer
                    << L"\n";

                foundAddress = true;
            }

            else if (family == AF_INET6)
            {
                sockaddr_in6* ipv6 =
                    reinterpret_cast<sockaddr_in6*>(
                        address->Address.lpSockaddr
                    );

                addressPointer =
                    &(ipv6->sin6_addr);

                InetNtopW(
                    AF_INET6,
                    addressPointer,
                    addressBuffer,
                    INET6_ADDRSTRLEN
                );

                report
                    << L"IPv6 Address: "
                    << addressBuffer
                    << L"\n";

                foundAddress = true;
            }
        }

        if (!foundAddress)
        {
            report << L"IP Address: None\n";
        }

        report << L"\n";

        adapterNumber++;
    }
}

wstring GetComputerNameString()
{
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1];

    DWORD size =
        MAX_COMPUTERNAME_LENGTH + 1;

    if (GetComputerNameW(name, &size))
        return name;

    return L"Unknown-PC";
}

wstring GetTimestamp()
{
    time_t currentTime = time(nullptr);

    tm localTime{};

    localtime_s(
        &localTime,
        &currentTime
    );

    wstringstream output;

    output
        << put_time(
            &localTime,
            L"%Y-%m-%d_%H-%M-%S"
        );

    return output.str();
}

int wmain()
{
    HRESULT result =
        CoInitializeEx(
            nullptr,
            COINIT_MULTITHREADED
        );

    if (FAILED(result))
    {
        wcerr << L"Unable to initialize COM.\n";
        return 1;
    }

    result = CoInitializeSecurity(
        nullptr,
        -1,
        nullptr,
        nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE,
        nullptr
    );

    if (FAILED(result) &&
        result != RPC_E_TOO_LATE)
    {
        wcerr << L"Unable to initialize COM security.\n";

        CoUninitialize();

        return 1;
    }

    IWbemLocator* locator = nullptr;

    result = CoCreateInstance(
        CLSID_WbemLocator,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        reinterpret_cast<void**>(&locator)
    );

    if (FAILED(result))
    {
        wcerr << L"Unable to create WMI locator.\n";

        CoUninitialize();

        return 1;
    }

    IWbemServices* service = nullptr;

    result = locator->ConnectServer(
        bstr_t(L"ROOT\\CIMV2"),
        nullptr,
        nullptr,
        nullptr,
        0,
        nullptr,
        nullptr,
        &service
    );

    if (FAILED(result))
    {
        wcerr << L"Unable to connect to WMI.\n";

        locator->Release();

        CoUninitialize();

        return 1;
    }

    result = CoSetProxyBlanket(
        service,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE
    );

    if (FAILED(result))
    {
        wcerr << L"Unable to configure WMI connection.\n";

        service->Release();
        locator->Release();

        CoUninitialize();

        return 1;
    }

    wstringstream report;

    wstring computerName =
        GetComputerNameString();

    report
        << L"Computer Name: "
        << computerName
        << L"\n\n";

    AddWMISection(
        service,
        report,
        L"Computer",
        L"SELECT Manufacturer, Model FROM Win32_ComputerSystem",
        {
            {L"Manufacturer", L"Manufacturer"},
            {L"Model", L"Model"}
        }
    );

    AddWMISection(
        service,
        report,
        L"CPU",
        L"SELECT Name, Manufacturer, NumberOfCores, "
        L"NumberOfLogicalProcessors, MaxClockSpeed "
        L"FROM Win32_Processor",
        {
            {L"Name", L"Name"},
            {L"Manufacturer", L"Manufacturer"},
            {L"Cores", L"NumberOfCores"},
            {L"Logical Processors", L"NumberOfLogicalProcessors"},
            {L"Maximum Clock Speed (MHz)", L"MaxClockSpeed"}
        }
    );

    AddWMISection(
        service,
        report,
        L"RAM Module",
        L"SELECT Manufacturer, PartNumber, Capacity, Speed "
        L"FROM Win32_PhysicalMemory",
        {
            {L"Manufacturer", L"Manufacturer"},
            {L"Part Number", L"PartNumber"},
            {L"Capacity", L"Capacity"},
            {L"Speed (MHz)", L"Speed"}
        }
    );

    AddWMISection(
        service,
        report,
        L"Storage Drive",
        L"SELECT Model, Manufacturer, InterfaceType, "
        L"Size, SerialNumber "
        L"FROM Win32_DiskDrive",
        {
            {L"Model", L"Model"},
            {L"Manufacturer", L"Manufacturer"},
            {L"Interface", L"InterfaceType"},
            {L"Size", L"Size"},
            {L"Serial Number", L"SerialNumber"}
        }
    );

    AddWMISection(
        service,
        report,
        L"GPU",
        L"SELECT Name, AdapterCompatibility, DriverVersion "
        L"FROM Win32_VideoController",
        {
            {L"Name", L"Name"},
            {L"Manufacturer", L"AdapterCompatibility"},
            {L"Driver Version", L"DriverVersion"}
        }
    );

    AddWMISection(
        service,
        report,
        L"Motherboard",
        L"SELECT Manufacturer, Product, Version, SerialNumber "
        L"FROM Win32_BaseBoard",
        {
            {L"Manufacturer", L"Manufacturer"},
            {L"Product", L"Product"},
            {L"Version", L"Version"},
            {L"Serial Number", L"SerialNumber"}
        }
    );

    AddWMISection(
        service,
        report,
        L"Operating System",
        L"SELECT Caption, Version, BuildNumber, OSArchitecture "
        L"FROM Win32_OperatingSystem",
        {
            {L"Name", L"Caption"},
            {L"Version", L"Version"},
            {L"Build Number", L"BuildNumber"},
            {L"Architecture", L"OSArchitecture"}
        }
    );

    AddNetworkInformation(report);

    wchar_t exePath[MAX_PATH];

    GetModuleFileNameW(
        nullptr,
        exePath,
        MAX_PATH
    );

    filesystem::path programPath(exePath);

    filesystem::path outputDirectory =
        programPath.parent_path();

    wstring fileName =
        computerName +
        L"_Specs_" +
        GetTimestamp() +
        L".txt";

    filesystem::path outputPath =
        outputDirectory / fileName;

    wofstream outputFile(outputPath);

    if (!outputFile)
    {
        wcerr << L"Unable to create report file.\n";
    }
    else
    {
        outputFile << report.str();

        outputFile.close();

        wcout << L"\nComputer information collected successfully.\n\n";

        wcout
            << L"Report saved to:\n"
            << outputPath
            << L"\n\n";
    }

    service->Release();
    locator->Release();

    CoUninitialize();

    wcout << L"Press Enter to exit.";

    wcin.get();

    return 0;
}