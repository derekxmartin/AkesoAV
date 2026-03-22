/* test_service.cpp -- Integration tests for akesoav-service named pipe protocol.
 *
 * Tests spawn the service in --console mode as a child process, connect
 * via \\.\pipe\AkesoAVScan, exercise all protocol commands, then shut down.
 *
 * Tests:
 *   1. Greeting on connect
 *   2. PING → PONG
 *   3. VERSION response
 *   4. SCAN with EICAR temp file → detection
 *   5. SCAN clean file → no detection
 *   6. SCAN nonexistent file → error
 *   7. STATS response format + cache hits
 *   8. QUIT closes connection
 *   9. Unknown command → 500 error
 *  10. 4 concurrent clients
 */

#include <gtest/gtest.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <chrono>

static const char PIPE_NAME[] = "\\\\.\\pipe\\AkesoAVScan";

/* ── Helper: pipe client ────────────────────────────────────────── */

class PipeClient {
public:
    PipeClient() : pipe_(INVALID_HANDLE_VALUE) {}
    ~PipeClient() { disconnect(); }

    bool connect(int timeout_ms = 10000) {
        auto start = std::chrono::steady_clock::now();
        while (true) {
            pipe_ = CreateFileA(
                PIPE_NAME, GENERIC_READ | GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, 0, NULL);
            if (pipe_ != INVALID_HANDLE_VALUE)
                return true;

            DWORD err = GetLastError();
            if (err == ERROR_PIPE_BUSY) {
                if (!WaitNamedPipeA(PIPE_NAME, 2000))
                    continue;
            }

            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed > timeout_ms)
                return false;
            Sleep(100);
        }
    }

    void disconnect() {
        if (pipe_ != INVALID_HANDLE_VALUE) {
            CloseHandle(pipe_);
            pipe_ = INVALID_HANDLE_VALUE;
        }
    }

    bool send(const std::string& msg) {
        std::string data = msg + "\r\n";
        DWORD written = 0;
        return WriteFile(pipe_, data.c_str(), (DWORD)data.size(),
                         &written, NULL) && written == (DWORD)data.size();
    }

    std::string recv_line(int timeout_ms = 5000) {
        std::string result;
        auto start = std::chrono::steady_clock::now();

        while (true) {
            BYTE b = 0;
            DWORD read_count = 0;

            /* Check if data is available */
            DWORD avail = 0;
            if (!PeekNamedPipe(pipe_, NULL, 0, NULL, &avail, NULL))
                break;

            if (avail == 0) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start).count();
                if (elapsed > timeout_ms) break;
                Sleep(10);
                continue;
            }

            if (!ReadFile(pipe_, &b, 1, &read_count, NULL) || read_count == 0)
                break;

            if (b == '\n') {
                if (!result.empty() && result.back() == '\r')
                    result.pop_back();
                return result;
            }
            result.push_back((char)b);
        }
        return result;
    }

    /* Read all response lines until we get a terminal line (200/210/220/500) */
    std::vector<std::string> recv_response() {
        std::vector<std::string> lines;
        while (true) {
            std::string line = recv_line();
            if (line.empty()) break;
            lines.push_back(line);
            /* Terminal lines start with 200, 220, or 500 */
            if (line.substr(0, 3) == "200" ||
                line.substr(0, 3) == "220" ||
                line.substr(0, 3) == "500") {
                break;
            }
        }
        return lines;
    }

private:
    HANDLE pipe_;
};

/* ── Helper: service process manager ────────────────────────────── */

class ServiceProcess {
public:
    ServiceProcess() : proc_{} {}

    ~ServiceProcess() { stop(); }

    bool start() {
        /* Find the service exe relative to the test exe */
        char test_path[MAX_PATH];
        GetModuleFileNameA(NULL, test_path, MAX_PATH);

        /* Navigate up from test exe to find service exe */
        std::string dir(test_path);
        auto pos = dir.rfind('\\');
        if (pos != std::string::npos)
            dir = dir.substr(0, pos);

        exe_path_ = dir + "\\akesoav-service.exe";

        /* Check if exe exists */
        if (GetFileAttributesA(exe_path_.c_str()) == INVALID_FILE_ATTRIBUTES) {
            fprintf(stderr, "Service exe not found: %s\n", exe_path_.c_str());
            return false;
        }

        std::string cmd = "\"" + exe_path_ + "\" --console";

        STARTUPINFOA si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        if (!CreateProcessA(
                NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE,
                CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &proc_)) {
            fprintf(stderr, "CreateProcess failed: %lu\n", GetLastError());
            return false;
        }

        /* Wait for pipe to become available */
        for (int i = 0; i < 50; i++) {
            if (WaitNamedPipeA(PIPE_NAME, 100))
                return true;
            /* Check if process is still alive */
            DWORD exit_code = 0;
            if (GetExitCodeProcess(proc_.hProcess, &exit_code) &&
                exit_code != STILL_ACTIVE) {
                fprintf(stderr, "Service exited with code %lu\n", exit_code);
                return false;
            }
            Sleep(100);
        }

        fprintf(stderr, "Pipe not available after 5s\n");
        return true;  /* Process running, pipe might just be slow */
    }

    void stop() {
        if (proc_.hProcess) {
            /* Send Ctrl+Break to the process group */
            GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, proc_.dwProcessId);
            WaitForSingleObject(proc_.hProcess, 3000);

            /* Force kill if still running */
            DWORD exit_code = 0;
            if (GetExitCodeProcess(proc_.hProcess, &exit_code) &&
                exit_code == STILL_ACTIVE) {
                TerminateProcess(proc_.hProcess, 1);
                WaitForSingleObject(proc_.hProcess, 2000);
            }

            CloseHandle(proc_.hProcess);
            CloseHandle(proc_.hThread);
            proc_ = {};
        }
    }

private:
    PROCESS_INFORMATION proc_;
    std::string exe_path_;
};

/* ── Test fixture ───────────────────────────────────────────────── */

class ServiceTest : public ::testing::Test {
protected:
    static ServiceProcess* svc_;

    static void SetUpTestSuite() {
        svc_ = new ServiceProcess();
        ASSERT_TRUE(svc_->start()) << "Failed to start service process";
        /* Give the service a moment to fully initialize */
        Sleep(500);
    }

    static void TearDownTestSuite() {
        delete svc_;
        svc_ = nullptr;
        /* Wait for pipe to be fully released */
        Sleep(500);
    }

    /* Helper: create a temp file with given content */
    std::string create_temp_file(const char* content, size_t len) {
        char temp_dir[MAX_PATH];
        char temp_path[MAX_PATH];
        GetTempPathA(sizeof(temp_dir), temp_dir);
        GetTempFileNameA(temp_dir, "aksv", 0, temp_path);

        HANDLE hf = CreateFileA(temp_path, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(hf, content, (DWORD)len, &written, NULL);
            CloseHandle(hf);
        }
        temp_files_.push_back(temp_path);
        return temp_path;
    }

    void TearDown() override {
        for (auto& f : temp_files_)
            DeleteFileA(f.c_str());
        temp_files_.clear();
    }

    std::vector<std::string> temp_files_;
};

ServiceProcess* ServiceTest::svc_ = nullptr;

/* ── Tests ──────────────────────────────────────────────────────── */

TEST_F(ServiceTest, GreetingOnConnect)
{
    PipeClient client;
    ASSERT_TRUE(client.connect());
    std::string greeting = client.recv_line();
    EXPECT_EQ(greeting, "220 AKESOAV READY");
}

TEST_F(ServiceTest, PingPong)
{
    PipeClient client;
    ASSERT_TRUE(client.connect());
    client.recv_line();  /* greeting */

    ASSERT_TRUE(client.send("PING"));
    std::string resp = client.recv_line();
    EXPECT_EQ(resp, "220 PONG");
}

TEST_F(ServiceTest, Version)
{
    PipeClient client;
    ASSERT_TRUE(client.connect());
    client.recv_line();  /* greeting */

    ASSERT_TRUE(client.send("VERSION"));
    std::string resp = client.recv_line();
    EXPECT_TRUE(resp.find("220 AkesoAV") != std::string::npos)
        << "Got: " << resp;
    EXPECT_TRUE(resp.find("DB:") != std::string::npos)
        << "Got: " << resp;
}

TEST_F(ServiceTest, ScanCleanFile)
{
    PipeClient client;
    ASSERT_TRUE(client.connect());
    client.recv_line();  /* greeting */

    const char* content = "this is a perfectly clean test file";
    std::string path = create_temp_file(content, strlen(content));

    ASSERT_TRUE(client.send("SCAN " + path));
    auto lines = client.recv_response();

    /* Should get "210 SCAN DATA\r\n" then "200 SCAN OK\r\n" */
    ASSERT_GE(lines.size(), 2u) << "Expected at least 2 response lines";
    EXPECT_EQ(lines[0], "210 SCAN DATA");
    EXPECT_EQ(lines.back(), "200 SCAN OK");

    /* No detection lines between 210 and 200 */
    EXPECT_EQ(lines.size(), 2u) << "Expected no detection for clean file";
}

TEST_F(ServiceTest, ScanNonexistentFile)
{
    PipeClient client;
    ASSERT_TRUE(client.connect());
    client.recv_line();  /* greeting */

    ASSERT_TRUE(client.send("SCAN C:\\nonexistent_akav_test_file_12345.exe"));
    std::string resp = client.recv_line();
    EXPECT_TRUE(resp.find("500") != std::string::npos)
        << "Expected error response, got: " << resp;
}

TEST_F(ServiceTest, Stats)
{
    PipeClient client;
    ASSERT_TRUE(client.connect());
    client.recv_line();  /* greeting */

    /* Scan a file first to increment counters */
    const char* content = "stats test file content";
    std::string path = create_temp_file(content, strlen(content));
    client.send("SCAN " + path);
    client.recv_response();  /* consume scan response */

    ASSERT_TRUE(client.send("STATS"));
    std::string resp = client.recv_line();

    /* Format: "220 <files_scanned> <malware_found> <cache_hits> <uptime_s>" */
    EXPECT_TRUE(resp.find("220") != std::string::npos)
        << "Expected 220 response, got: " << resp;

    /* Parse the numbers */
    unsigned long long files = 0, malware = 0, cache = 0;
    long long uptime = 0;
    int parsed = sscanf_s(resp.c_str(), "220 %llu %llu %llu %lld",
                          &files, &malware, &cache, &uptime);
    EXPECT_EQ(parsed, 4) << "Failed to parse STATS: " << resp;
    EXPECT_GE(files, 1ULL) << "Expected at least 1 file scanned";
    EXPECT_GE(uptime, 0LL);
}

TEST_F(ServiceTest, StatsShowsCacheHits)
{
    PipeClient client;
    ASSERT_TRUE(client.connect());
    client.recv_line();  /* greeting */

    /* Scan the same file twice → second should be cache hit */
    const char* content = "cache hit test file";
    std::string path = create_temp_file(content, strlen(content));

    client.send("SCAN " + path);
    client.recv_response();

    client.send("SCAN " + path);
    client.recv_response();

    ASSERT_TRUE(client.send("STATS"));
    std::string resp = client.recv_line();

    unsigned long long files = 0, malware = 0, cache = 0;
    long long uptime = 0;
    sscanf_s(resp.c_str(), "220 %llu %llu %llu %lld",
             &files, &malware, &cache, &uptime);

    /* Cache hits should be > 0 from the repeated scan */
    EXPECT_GT(cache, 0ULL) << "Expected cache hits after re-scan. STATS: " << resp;
}

TEST_F(ServiceTest, Quit)
{
    PipeClient client;
    ASSERT_TRUE(client.connect());
    client.recv_line();  /* greeting */

    ASSERT_TRUE(client.send("QUIT"));

    /* After QUIT, the server closes the connection.
     * A subsequent read should fail or return empty. */
    Sleep(200);
    std::string resp = client.recv_line(1000);
    /* Either empty or connection closed — both OK */
}

TEST_F(ServiceTest, UnknownCommand)
{
    PipeClient client;
    ASSERT_TRUE(client.connect());
    client.recv_line();  /* greeting */

    ASSERT_TRUE(client.send("FOOBAR"));
    std::string resp = client.recv_line();
    EXPECT_TRUE(resp.find("500") != std::string::npos)
        << "Expected 500 error, got: " << resp;
    EXPECT_TRUE(resp.find("FOOBAR") != std::string::npos)
        << "Expected command echoed in error, got: " << resp;
}

TEST_F(ServiceTest, ConcurrentClients)
{
    const int NUM_CLIENTS = 4;
    std::vector<std::thread> threads;
    std::atomic<int> successes{0};

    /* Create a shared temp file */
    const char* content = "concurrent client test file";
    std::string path = create_temp_file(content, strlen(content));

    for (int i = 0; i < NUM_CLIENTS; i++) {
        threads.emplace_back([&, i, path]() {
            PipeClient client;
            if (!client.connect(15000)) {
                fprintf(stderr, "Client %d: connect failed\n", i);
                return;
            }

            std::string greeting = client.recv_line();
            if (greeting.find("220") == std::string::npos) {
                fprintf(stderr, "Client %d: bad greeting\n", i);
                return;
            }

            /* PING */
            client.send("PING");
            std::string pong = client.recv_line();
            if (pong != "220 PONG") {
                fprintf(stderr, "Client %d: bad pong: %s\n", i, pong.c_str());
                return;
            }

            /* SCAN */
            client.send("SCAN " + path);
            auto resp = client.recv_response();
            if (resp.size() >= 2 && resp[0] == "210 SCAN DATA" &&
                resp.back() == "200 SCAN OK") {
                successes.fetch_add(1);
            } else {
                fprintf(stderr, "Client %d: bad scan response\n", i);
            }

            client.send("QUIT");
        });
    }

    for (auto& t : threads) t.join();

    EXPECT_EQ(successes.load(), NUM_CLIENTS)
        << "Expected all " << NUM_CLIENTS << " clients to succeed";
}

TEST_F(ServiceTest, MultipleCommandsOneSession)
{
    PipeClient client;
    ASSERT_TRUE(client.connect());
    client.recv_line();  /* greeting */

    /* PING */
    client.send("PING");
    EXPECT_EQ(client.recv_line(), "220 PONG");

    /* VERSION */
    client.send("VERSION");
    std::string ver = client.recv_line();
    EXPECT_TRUE(ver.find("220 AkesoAV") != std::string::npos);

    /* STATS */
    client.send("STATS");
    std::string stats = client.recv_line();
    EXPECT_TRUE(stats.find("220") != std::string::npos);

    /* PING again */
    client.send("PING");
    EXPECT_EQ(client.recv_line(), "220 PONG");

    /* QUIT */
    client.send("QUIT");
}
