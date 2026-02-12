#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <conio.h>
#include <fstream>
#include <cstdio>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <ctime>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace Color {
    const char* Reset = "\033[0m";
    const char* Dim   = "\033[2m";
    const char* Bold  = "\033[1m";
    const char* White = "\033[97m";
    const char* Gray  = "\033[90m";
    const char* Green = "\033[32m";
    const char* Yel   = "\033[33m";
    const char* Red   = "\033[91m";
    const char* Cyan  = "\033[36m";
    const char* BgBar = "\033[48;5;236m";
    const char* BgAlt = "\033[48;5;234m";
}

static bool isPaused = false;
static std::ofstream logFile("connections.log", std::ios::app);

static void EnableAnsi() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

static int GetTermWidth() {
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info))
        return info.srWindow.Right - info.srWindow.Left + 1;
    return 120;
}

static std::string GetProcessName(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return "System";

    char buffer[MAX_PATH];
    DWORD size = MAX_PATH;

    if (QueryFullProcessImageNameA(hProcess, 0, buffer, &size)) {
        CloseHandle(hProcess);
        std::string fullPath(buffer);
        size_t pos = fullPath.find_last_of("\\");
        if (pos != std::string::npos)
            return fullPath.substr(pos + 1);
        return fullPath;
    }

    CloseHandle(hProcess);
    return "System";
}

static bool IsPrivateIP(const std::string& ip) {
    if (ip.rfind("192.168.", 0) == 0) return true;
    if (ip.rfind("10.", 0) == 0) return true;
    if (ip == "127.0.0.1" || ip == "0.0.0.0") return true;
    if (ip.rfind("172.", 0) == 0) {
        size_t dot = ip.find('.', 4);
        if (dot != std::string::npos) {
            int octet = std::stoi(ip.substr(4, dot - 4));
            return (octet >= 16 && octet <= 31);
        }
    }
    return false;
}

static bool IsSuspiciousPort(unsigned short port) {
    static const unsigned short ports[] = { 25, 135, 139, 445, 3389, 5985 };
    for (unsigned short p : ports)
        if (port == p) return true;
    return false;
}

static std::string Pad(const std::string& s, int w) {
    if ((int)s.size() >= w) return s.substr(0, w);
    return s + std::string(w - s.size(), ' ');
}

static std::string Timestamp() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    struct tm lt;
    localtime_s(&lt, &t);
    char buf[32];
    strftime(buf, sizeof(buf), "%H:%M:%S", &lt);
    return buf;
}

struct TcpEntry {
    std::string process;
    DWORD pid;
    std::string local;
    std::string remote;
    std::string remoteIp;
    unsigned short remotePort;
    bool isPublic;
    bool isSuspicious;
};

struct UdpEntry {
    std::string process;
    DWORD pid;
    std::string local;
};

static std::vector<TcpEntry> GetTcpConnections() {
    std::vector<TcpEntry> entries;
    PMIB_TCPTABLE_OWNER_PID pTable = nullptr;
    DWORD sz = 0;

    GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    pTable = (PMIB_TCPTABLE_OWNER_PID)malloc(sz);
    if (!pTable) return entries;

    if (GetExtendedTcpTable(pTable, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < pTable->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID& row = pTable->table[i];

            char localIp[INET_ADDRSTRLEN], remoteIp[INET_ADDRSTRLEN];
            sockaddr_in la{}, ra{};
            la.sin_addr.S_un.S_addr = row.dwLocalAddr;
            la.sin_port = row.dwLocalPort;
            ra.sin_addr.S_un.S_addr = row.dwRemoteAddr;
            ra.sin_port = row.dwRemotePort;

            if (!InetNtopA(AF_INET, &la.sin_addr, localIp, sizeof(localIp)))
                strcpy_s(localIp, "N/A");
            if (!InetNtopA(AF_INET, &ra.sin_addr, remoteIp, sizeof(remoteIp)))
                strcpy_s(remoteIp, "N/A");

            unsigned short lp = ntohs(la.sin_port);
            unsigned short rp = ntohs(ra.sin_port);

            TcpEntry e;
            e.process = GetProcessName(row.dwOwningPid);
            e.pid = row.dwOwningPid;
            e.local = std::string(localIp) + ":" + std::to_string(lp);
            e.remote = std::string(remoteIp) + ":" + std::to_string(rp);
            e.remoteIp = remoteIp;
            e.remotePort = rp;
            e.isPublic = !IsPrivateIP(remoteIp) && std::string(remoteIp) != "0.0.0.0";
            e.isSuspicious = IsSuspiciousPort(rp);
            entries.push_back(e);
        }
    }

    free(pTable);
    return entries;
}

static std::vector<UdpEntry> GetUdpListeners() {
    std::vector<UdpEntry> entries;
    PMIB_UDPTABLE_OWNER_PID pTable = nullptr;
    DWORD sz = 0;

    GetExtendedUdpTable(nullptr, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    pTable = (PMIB_UDPTABLE_OWNER_PID)malloc(sz);
    if (!pTable) return entries;

    if (GetExtendedUdpTable(pTable, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < pTable->dwNumEntries; i++) {
            MIB_UDPROW_OWNER_PID& row = pTable->table[i];

            char localIp[INET_ADDRSTRLEN];
            sockaddr_in la{};
            la.sin_addr.S_un.S_addr = row.dwLocalAddr;
            la.sin_port = row.dwLocalPort;

            if (!InetNtopA(AF_INET, &la.sin_addr, localIp, sizeof(localIp)))
                strcpy_s(localIp, "N/A");

            unsigned short lp = ntohs(la.sin_port);

            UdpEntry e;
            e.process = GetProcessName(row.dwOwningPid);
            e.pid = row.dwOwningPid;
            e.local = std::string(localIp) + ":" + std::to_string(lp);
            entries.push_back(e);
        }
    }

    free(pTable);
    return entries;
}

static void LogEntries(const std::vector<TcpEntry>& tcp, const std::vector<UdpEntry>& udp) {
    for (auto& e : tcp) {
        std::string flag;
        if (e.isPublic) flag += "PUBLIC ";
        if (e.isSuspicious) flag += "SUSPICIOUS";
        logFile << "TCP " << e.process << " (" << e.pid << ") "
                << e.local << " -> " << e.remote << " " << flag << "\n";
    }
    for (auto& e : udp)
        logFile << "UDP " << e.process << " (" << e.pid << ") " << e.local << "\n";
    logFile.flush();
}

static void RenderHeader(int w) {
    std::string ts = Timestamp();
    const char* sc = isPaused ? Color::Yel : Color::Green;
    const char* st = isPaused ? "PAUSED" : "LIVE";

    std::cout << Color::BgBar
              << Color::Bold << Color::White << "  NETMONITOR" << Color::Reset
              << Color::BgBar << Color::Dim << Color::Gray << "  v1.0" << Color::Reset
              << Color::BgBar;

    int gap = w - 20 - (int)strlen(st) - (int)ts.size() - 6;
    if (gap > 0) std::cout << std::string(gap, ' ');

    std::cout << sc << Color::Bold << " " << st << " " << Color::Reset
              << Color::BgBar << Color::Gray << "  " << ts << "  " << Color::Reset
              << "\n"
              << Color::Dim << Color::Gray
              << "  [P] Pause   [Ctrl+C] Exit   Log: connections.log"
              << Color::Reset << "\n\n";
}

static void RenderColumns(const std::vector<std::pair<std::string,int>>& cols) {
    std::cout << "  " << Color::BgAlt;
    for (auto& c : cols)
        std::cout << Color::Gray << Color::Bold << Pad(c.first, c.second);
    std::cout << Color::Reset << "\n";
}

static void RenderTcp(const std::vector<TcpEntry>& entries) {
    std::cout << Color::Bold << Color::Cyan << "  TCP Connections" << Color::Reset << "\n";

    std::vector<std::pair<std::string,int>> cols = {
        {"PROCESS", 26}, {"PID", 8}, {"LOCAL", 24}, {"REMOTE", 24}, {"FLAGS", 14}
    };
    RenderColumns(cols);

    int r = 0;
    for (auto& e : entries) {
        const char* bg = (r & 1) ? Color::BgAlt : "";

        std::string flags;
        const char* fc = Color::Gray;
        if (e.isSuspicious)      { flags = "ALERT";  fc = Color::Red; }
        else if (e.isPublic)     { flags = "PUBLIC"; fc = Color::Yel; }

        std::cout << "  " << bg
                  << Color::White << Pad(e.process, 26)
                  << Color::Gray  << Pad(std::to_string(e.pid), 8)
                  << Color::Dim   << Pad(e.local, 24)
                  << Color::White << Pad(e.remote, 24)
                  << fc           << Pad(flags, 14)
                  << Color::Reset << "\n";
        r++;
    }

    std::cout << Color::Dim << Color::Gray
              << "  " << entries.size() << " connections"
              << Color::Reset << "\n\n";
}

static void RenderUdp(const std::vector<UdpEntry>& entries) {
    std::cout << Color::Bold << Color::Cyan << "  UDP Listeners" << Color::Reset << "\n";

    std::vector<std::pair<std::string,int>> cols = {
        {"PROCESS", 26}, {"PID", 8}, {"LOCAL", 24}
    };
    RenderColumns(cols);

    int r = 0;
    for (auto& e : entries) {
        const char* bg = (r & 1) ? Color::BgAlt : "";
        std::cout << "  " << bg
                  << Color::White << Pad(e.process, 26)
                  << Color::Gray  << Pad(std::to_string(e.pid), 8)
                  << Color::Dim   << Pad(e.local, 24)
                  << Color::Reset << "\n";
        r++;
    }

    std::cout << Color::Dim << Color::Gray
              << "  " << entries.size() << " listeners"
              << Color::Reset << "\n";
}

static bool HandleKeyInput() {
    if (_kbhit()) {
        int key = _getch();
        if (key == 'p' || key == 'P') {
            isPaused = !isPaused;
            return true;
        }
    }
    return false;
}

int main() {
    EnableAnsi();

    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO ci;
    GetConsoleCursorInfo(hCon, &ci);
    ci.bVisible = FALSE;
    SetConsoleCursorInfo(hCon, &ci);

    std::vector<TcpEntry> tcpCache;
    std::vector<UdpEntry> udpCache;
    bool firstRun = true;

    while (true) {
        int w = GetTermWidth();

        if (!isPaused || firstRun) {
            tcpCache = GetTcpConnections();
            udpCache = GetUdpListeners();
            if (!isPaused)
                LogEntries(tcpCache, udpCache);
            firstRun = false;
        }

        std::cout << "\033[2J\033[H";
        RenderHeader(w);
        RenderTcp(tcpCache);
        RenderUdp(udpCache);
        std::cout << Color::Reset;

        if (isPaused) {
            while (isPaused) {
                if (HandleKeyInput()) break;
                Sleep(100);
            }
        } else {
            for (int i = 0; i < 30; i++) {
                if (HandleKeyInput()) break;
                Sleep(100);
            }
        }
    }

    logFile.close();
    return 0;
}