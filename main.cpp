#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <thread>
#include <fstream>
#include <mutex>
#include <cstdlib> 
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <algorithm>
#include <ctime>
#include <sqlite3.h>


using namespace std;


// All classes forward declarations
class ScannerStrategy;
class PingUtilityStrategy;
class PingSweepStrategy;
class NetworkScanner;
class PingUtility;
class PingSweep;
class CustomScanStrategy;
class CustomScanner;
class TCPPortScanStrategy;
class TCPPortScanner;
class UserInterface;
class CommonPortScanner;
class Host;
class Port;
class ScanDatabase;
class SQLiteDatabase;

// Port Class
class Port {
private:
    int portNumber;
    string protocol;  
    string serviceName;
    bool isOpen;
    
public:
    Port(int port, const string& proto = "TCP") 
        : portNumber(port), protocol(proto), isOpen(false) {
        setServiceName();
    }
    
    void setOpen(bool status) { isOpen = status; }
    void setService(const string& service) { serviceName = service; }
    
    void setServiceName() {
        map<int, string> portServices = {
            {21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"},
            {53, "DNS"}, {80, "HTTP"}, {110, "POP3"}, {443, "HTTPS"},
            {993, "IMAPS"}, {995, "POP3S"}, {1433, "MSSQL"}, {3306, "MySQL"},
            {3389, "RDP"}, {5432, "PostgreSQL"}, {27017, "MongoDB"}
        };
        
        if (portServices.find(portNumber) != portServices.end()) {
            serviceName = portServices[portNumber];
        } else {
            serviceName = "Unknown";
        }
    }
    
    // Getters
    int getNumber() const { return portNumber; }
    string getProtocol() const { return protocol; }
    string getService() const { return serviceName; }
    bool getStatus() const { return isOpen; }
    
    void display() const {
        cout << "Port " << portNumber << " (" << serviceName << "/" << protocol << ") - " 
             << (isOpen ? "OPEN" : "CLOSED") << endl;
    }
};

// Host Class
class Host {
private:
    string ipAddress;
    string hostname;
    bool isActive;
    vector<Port> openPorts;
    
public:
    Host(const string& ip) : ipAddress(ip), isActive(false) {}
    
    void setActive(bool active) { isActive = active; }
    void setHostname(const string& name) { hostname = name; }
    
    void addOpenPort(const Port& port) { 
        openPorts.push_back(port); 
    }
    
    void clearPorts() {
        openPorts.clear();
    }
    
    string getIP() const { return ipAddress; }
    string getHostname() const { return hostname; }
    bool getActive() const { return isActive; }
    vector<Port> getOpenPorts() const { return openPorts; }
    
    bool hasOpenPorts() const {
        return !openPorts.empty();
    }
    
    void display() const {
        cout << "\nHost: " << ipAddress;
        if (!hostname.empty()) cout << " (" << hostname << ")";
        cout << " - " << (isActive ? "ACTIVE" : "INACTIVE") << endl;
        
        if (hasOpenPorts()) {
            cout << "Open Ports:" << endl;
            for (const auto& port : openPorts) {
                cout << "  ";
                port.display();
            }
        } else {
            cout << "  No open ports found" << endl;
        }
    }
};

// SQLite Database Class
class SQLiteDatabase {
private:
    sqlite3* db;
    string dbFilename;
    mutex dbMutex;
    
public:
    SQLiteDatabase(const string& filename = "network_scanner.db") : dbFilename(filename) {
        initializeDatabase();
    }
    
    ~SQLiteDatabase() {
        if (db) {
            sqlite3_close(db);
        }
    }
    
    bool initializeDatabase() {
        lock_guard<mutex> lock(dbMutex);
        int rc = sqlite3_open(dbFilename.c_str(), &db);
        if (rc) {
            cerr << "Can't open database: " << sqlite3_errmsg(db) << endl;
            return false;
        }
        
        // Create tables if they don't exist
        const char* createScanSessionTable = 
            "CREATE TABLE IF NOT EXISTS scan_sessions ("
            "session_id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "start_time TEXT NOT NULL,"
            "end_time TEXT,"
            "target_range TEXT,"
            "hosts_scanned INTEGER,"
            "active_hosts INTEGER);";
        
        const char* createHostsTable = 
            "CREATE TABLE IF NOT EXISTS hosts ("
            "host_id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "session_id INTEGER,"
            "ip_address TEXT NOT NULL,"
            "hostname TEXT,"
            "is_active BOOLEAN,"
            "scan_timestamp TEXT,"
            "FOREIGN KEY(session_id) REFERENCES scan_sessions(session_id));";
        
        const char* createPortsTable = 
            "CREATE TABLE IF NOT EXISTS ports ("
            "port_id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "host_id INTEGER,"
            "port_number INTEGER,"
            "protocol TEXT,"
            "service_name TEXT,"
            "is_open BOOLEAN,"
            "scan_timestamp TEXT,"
            "FOREIGN KEY(host_id) REFERENCES hosts(host_id));";
        
        executeSQL(createScanSessionTable);
        executeSQL(createHostsTable);
        executeSQL(createPortsTable);
        
        cout << "Database initialized: " << dbFilename << endl;
        return true;
    }
    
    int startNewSession(const string& targetRange = "") {
        lock_guard<mutex> lock(dbMutex);
        time_t now = time(0);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        
        string sql = "INSERT INTO scan_sessions (start_time, target_range) VALUES ('" + 
                    string(timestamp) + "', '" + targetRange + "');";
        
        executeSQL(sql);
        return sqlite3_last_insert_rowid(db);
    }
    
    void endSession(int sessionId, int hostsScanned, int activeHosts) {
        lock_guard<mutex> lock(dbMutex);
        time_t now = time(0);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        
        string sql = "UPDATE scan_sessions SET end_time = '" + string(timestamp) + 
                    "', hosts_scanned = " + to_string(hostsScanned) + 
                    ", active_hosts = " + to_string(activeHosts) + 
                    " WHERE session_id = " + to_string(sessionId) + ";";
        
        executeSQL(sql);
    }
    
    void saveHost(int sessionId, const Host& host) {
        lock_guard<mutex> lock(dbMutex);
        time_t now = time(0);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        
        string sql = "INSERT INTO hosts (session_id, ip_address, hostname, is_active, scan_timestamp) "
                    "VALUES (" + to_string(sessionId) + ", '" + host.getIP() + "', '" + 
                    host.getHostname() + "', " + (host.getActive() ? "1" : "0") + ", '" + 
                    string(timestamp) + "');";
        
        executeSQL(sql);
        int hostId = sqlite3_last_insert_rowid(db);
        
        // Save ports for this host
        for (const auto& port : host.getOpenPorts()) {
            savePort(hostId, port);
        }
    }
    
    void savePort(int hostId, const Port& port) {
        lock_guard<mutex> lock(dbMutex);
        time_t now = time(0);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        
        string sql = "INSERT INTO ports (host_id, port_number, protocol, service_name, is_open, scan_timestamp) "
                    "VALUES (" + to_string(hostId) + ", " + to_string(port.getNumber()) + ", '" + 
                    port.getProtocol() + "', '" + port.getService() + "', " + 
                    (port.getStatus() ? "1" : "0") + ", '" + string(timestamp) + "');";
        
        executeSQL(sql);
    }
    
    vector<Host> getSessionResults(int sessionId) {
        lock_guard<mutex> lock(dbMutex);
        vector<Host> hosts;
        
        string sql = "SELECT ip_address, hostname, is_active FROM hosts WHERE session_id = " + 
                    to_string(sessionId) + ";";
        
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                string ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                string hostname = sqlite3_column_text(stmt, 1) ? 
                                 reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)) : "";
                bool isActive = sqlite3_column_int(stmt, 2);
                
                Host host(ip);
                host.setHostname(hostname);
                host.setActive(isActive);
                
                // Get ports for this host
                vector<Port> ports = getHostPorts(ip, sessionId);
                for (const auto& port : ports) {
                    host.addOpenPort(port);
                }
                
                hosts.push_back(host);
            }
        }
        sqlite3_finalize(stmt);
        return hosts;
    }
    
    void displaySessionHistory() {
        lock_guard<mutex> lock(dbMutex);
        cout << "\n=== SCAN SESSION HISTORY ===" << endl;
        
        string sql = "SELECT session_id, start_time, target_range, hosts_scanned, active_hosts "
                    "FROM scan_sessions ORDER BY session_id DESC LIMIT 10;";
        
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                int sessionId = sqlite3_column_int(stmt, 0);
                string startTime = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                string targetRange = sqlite3_column_text(stmt, 2) ? 
                                   reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)) : "N/A";
                int hostsScanned = sqlite3_column_int(stmt, 3);
                int activeHosts = sqlite3_column_int(stmt, 4);
                
                cout << "Session " << sessionId << " | " << startTime 
                     << " | Target: " << targetRange 
                     << " | Hosts: " << activeHosts << "/" << hostsScanned << " active" << endl;
            }
        }
        sqlite3_finalize(stmt);
    }
    
    void displaySessionDetails(int sessionId) {
        lock_guard<mutex> lock(dbMutex);
        cout << "\n=== DETAILED RESULTS - Session " << sessionId << " ===" << endl;
        
        vector<Host> hosts = getSessionResults(sessionId);
        int activeCount = 0;
        
        for (const auto& host : hosts) {
            if (host.getActive()) {
                activeCount++;
                host.display();
            }
        }
        
        cout << "\nSUMMARY: " << activeCount << " active hosts found." << endl;
    }

private:
    vector<Port> getHostPorts(const string& ip, int sessionId) {
        vector<Port> ports;
        
        string sql = "SELECT p.port_number, p.protocol, p.service_name, p.is_open "
                    "FROM ports p JOIN hosts h ON p.host_id = h.host_id "
                    "WHERE h.ip_address = '" + ip + "' AND h.session_id = " + to_string(sessionId) + ";";
        
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                int portNum = sqlite3_column_int(stmt, 0);
                string protocol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                string service = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                bool isOpen = sqlite3_column_int(stmt, 3);
                
                Port port(portNum, protocol);
                port.setService(service);
                port.setOpen(isOpen);
                ports.push_back(port);
            }
        }
        sqlite3_finalize(stmt);
        return ports;
    }
    
    bool executeSQL(const string& sql) {
        char* errorMsg = nullptr;
        int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errorMsg);
        if (rc != SQLITE_OK) {
            cerr << "SQL error: " << errorMsg << endl;
            sqlite3_free(errorMsg);
            return false;
        }
        return true;
    }
};

// Updated ScanDatabase class 
class ScanDatabase {
private:
    shared_ptr<SQLiteDatabase> sqliteDB;
    int currentSessionId;
    vector<Host> currentSessionHosts;
    
public:
    ScanDatabase() {
        sqliteDB = make_shared<SQLiteDatabase>();
        currentSessionId = -1;
    }
    
    void startNewSession(const string& targetRange = "") {
        currentSessionId = sqliteDB->startNewSession(targetRange);
        currentSessionHosts.clear();
        cout << "Started new scan session: " << currentSessionId << endl;
    }
    
    void endSession() {
        if (currentSessionId != -1) {
            int hostsScanned = currentSessionHosts.size();
            int activeHosts = count_if(currentSessionHosts.begin(), currentSessionHosts.end(),
                                     [](const Host& h) { return h.getActive(); });
            sqliteDB->endSession(currentSessionId, hostsScanned, activeHosts);
            cout << "Ended scan session: " << currentSessionId << endl;
        }
    }
    
    void addHost(const Host& host) {
        if (currentSessionId != -1) {
            currentSessionHosts.push_back(host);
            sqliteDB->saveHost(currentSessionId, host);
        }
    }
    
    void updateHostPorts(const string& ip, const vector<Port>& openPorts) {
        if (currentSessionId != -1) {
            // Find host and update its ports
            for (auto& host : currentSessionHosts) {
                if (host.getIP() == ip) {
                    host.clearPorts();
                    for (const auto& port : openPorts) {
                        host.addOpenPort(port);
                    }
                    // Update in database by re-saving the host
                    sqliteDB->saveHost(currentSessionId, host);
                    break;
                }
            }
        }
    }
    
    void saveToFile(const string& filename = "") {
        // Still support text file export
        string saveFile = filename.empty() ? "scan_results.txt" : filename;
        ofstream file(saveFile);
        
        if (!file.is_open()) {
            cout << "Error: Could not save results to " << saveFile << endl;
            return;
        }
        
        file << "Network Scan Results\n";
        file << "====================\n";
        file << "Scan Session: " << currentSessionId << "\n";
        file << "Scan Time: " << getCurrentTime() << "\n\n";
        
        int activeCount = 0;
        for (const auto& host : currentSessionHosts) {
            if (host.getActive()) {
                activeCount++;
                file << "Host: " << host.getIP();
                if (!host.getHostname().empty()) 
                    file << " (" << host.getHostname() << ")";
                file << "\nStatus: ACTIVE\n";
                
                if (host.hasOpenPorts()) {
                    file << "Open Ports:\n";
                    for (const auto& port : host.getOpenPorts()) {
                        file << "  Port " << port.getNumber() << " (" 
                             << port.getService() << "/" << port.getProtocol() 
                             << ") - OPEN\n";
                    }
                } else {
                    file << "Open Ports: None\n";
                }
                file << "--------------------\n";
            }
        }
        
        file << "\nSummary: " << activeCount << " active hosts found out of " 
             << currentSessionHosts.size() << " scanned.\n";
        
        file.close();
        cout << "Results saved to: " << saveFile << endl;
    }
    
    void displayResults() const {
        cout << "\n=== CURRENT SESSION RESULTS ===" << endl;
        int activeCount = 0;
        
        for (const auto& host : currentSessionHosts) {
            if (host.getActive()) {
                activeCount++;
                host.display();
            }
        }
        
        cout << "\nSUMMARY: " << activeCount << " active hosts found out of " 
             << currentSessionHosts.size() << " scanned." << endl;
    }
    
    void displayHistory() {
        sqliteDB->displaySessionHistory();
    }
    
    void displaySessionDetails(int sessionId) {
        sqliteDB->displaySessionDetails(sessionId);
    }
    
    vector<Host> getActiveHosts() const {
        vector<Host> activeHosts;
        for (const auto& host : currentSessionHosts) {
            if (host.getActive()) {
                activeHosts.push_back(host);
            }
        }
        return activeHosts;
    }
    
    int getCurrentSessionId() const { return currentSessionId; }

private:
    string getCurrentTime() const {
        time_t now = time(0);
        char timeStr[100];
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localtime(&now));
        return string(timeStr);
    }
};


// Scanner Strategy interface
class ScannerStrategy {
public:
    virtual void executeScan(const string& target) = 0;
    virtual ~ScannerStrategy() = default;
};

// Network Scanner main class
class NetworkScanner {
protected:
    string operatingSystem;
    shared_ptr<ScanDatabase> database;
public:
    NetworkScanner(shared_ptr<ScanDatabase> db) : database(db) {
        setOperatingSystem();
    }
    virtual void scan() = 0;
    virtual void displayResults() = 0;
    virtual ~NetworkScanner() = default;
    
    void setOperatingSystem() {
        #ifdef _WIN32
            operatingSystem = "Windows";
        #elif __linux__
            operatingSystem = "Linux";
        #elif __APPLE__
            operatingSystem = "MacOS";
        #else
            operatingSystem = "Unknown";
        #endif
        cout << "Operating System detected: " << operatingSystem << endl;
    }
    string getOS() const { return operatingSystem; }
};
// Common Port Scanner 
class CommonPortScanner {
private:
    vector<int> commonPorts;
    
public:
    CommonPortScanner() {
        commonPorts = {21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 
                      1433, 3306, 3389, 5432, 8080, 8443, 27017};
    }
    
    vector<Port> scanCommonPorts(const string& targetIP) {
        vector<Port> openPorts;
        vector<thread> threads;
        mutex portsMutex;
        
        cout << "Scanning common ports on " << targetIP << "..." << endl;
        
        for (int port : commonPorts) {
            threads.emplace_back([this, targetIP, port, &openPorts, &portsMutex]() {
                if (isPortOpen(targetIP, port)) {
                    Port openPort(port);
                    openPort.setOpen(true);
                    lock_guard<mutex> lock(portsMutex);
                    openPorts.push_back(openPort);
                }
            });
        }
        
        for (auto& thread : threads) {
            thread.join();
        }
        
        return openPorts;
    }
    
private:
    bool isPortOpen(const string& target, int port) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) return false;

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(target.c_str());

        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);

        int result = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
        close(sockfd);
        
        return result == 0;
    }
};


// Derived Strategy class for Ping Utility scanning
class PingUtilityStrategy : public ScannerStrategy {
private:
    string operatingSystem;
public:
    PingUtilityStrategy(const string& os) : operatingSystem(os) {}
    
    void displayMenu() {
        cout << "\nPing Options Menu:" << endl;
        cout << "1. Basic ping (4 packets)" << endl;
        cout << "2. Ping with count" << endl;
        cout << "3. Continuous ping (Ctrl+C to stop)" << endl;
        cout << "4. Ping with packet size" << endl;
        cout << "5. Ping with timeout" << endl;
        cout << "6. Help" << endl;
        cout << "7. Exit" << endl;
    }

    void pingBasic(const string& target) {
        cout << "Executing: ping " << target << endl;
        cout << "-----------------------------------------" << endl;
        
        string command;
        if(operatingSystem == "Windows")
            command = "ping " + target;
        else
            command = "ping -c 4 " + target;
        
        int result = system(command.c_str());
        cout << "-----------------------------------------" << endl;
        cout << "Command exited with code: " << result << endl;
    }

    void pingCount(const string& target, int count) {
        cout << "Executing: ping " << target << " with count " << count << endl;
        cout << "-----------------------------------------" << endl;
        
        string command;
        if(operatingSystem == "Windows"){
            command = "ping -n " + to_string(count) + " " + target;
        }
        else{
            command = "ping -c " + to_string(count) + " " + target;
        }
        
        int result = system(command.c_str());
        cout << "-----------------------------------------" << endl;
        cout << "Command exited with code: " << result << endl;
    }

    void pingContinuous(const string& target) {
        cout << "Executing: continuous ping to " << target << endl;
        cout << "Press Ctrl+C to stop" << endl;
        cout << "-----------------------------------------" << endl;
        
        string command;
        if(operatingSystem == "Windows")
            command = "ping -t " + target;
        else
            command = "ping " + target;
        
        int result = system(command.c_str());
        cout << "-----------------------------------------" << endl;
        cout << "Command exited with code: " << result << endl;
    }

    void pingSize(const string& target, int packetSize) {
        cout << "Executing: ping " << target << " with packet size " << packetSize << endl;
        cout << "-----------------------------------------" << endl;
        
        string command;
        if(operatingSystem == "Windows")
            command = "ping -l " + to_string(packetSize) + " " + target;
        else
            command = "ping -s " + to_string(packetSize) + " " + target;
        
        int result = system(command.c_str());
        cout << "-----------------------------------------" << endl;
        cout << "Command exited with code: " << result << endl;
    }

    void pingTimeout(const string& target, int timeoutSec) {
        cout << "Executing: ping " << target << " with timeout " << timeoutSec << " seconds" << endl;
        cout << "-----------------------------------------" << endl;
        
        string command;
        if(operatingSystem == "Windows")
            command = "ping -w " + to_string(timeoutSec * 1000) + " " + target;
        else
            command = "ping -W " + to_string(timeoutSec) + " " + target;
        
        int result = system(command.c_str());
        cout << "-----------------------------------------" << endl;
        cout << "Command exited with code: " << result << endl;
    }

    void pingHelp() {
        cout << "\nPing Command Help:" << endl;
        cout << "-------------------" << endl;
        cout << "This program executes actual ping commands using your system's ping utility." << endl;
        cout << endl;
        cout << "Options explained:" << endl;
        cout << "1. Basic ping: Sends 4 ICMP echo requests to the target" << endl;
        cout << "2. Ping with count: Sends a specified number of packets" << endl;
        cout << "3. Continuous ping: Sends packets until stopped with Ctrl+C" << endl;
        cout << "4. Ping with packet size: Specifies the size of the data payload" << endl;
        cout << "5. Ping with timeout: Sets the timeout to wait for each reply" << endl;
        cout << endl;
        
        if(operatingSystem == "Windows"){
            cout << "Using Windows ping command syntax" << endl;
            cout << "For more info: ping /?" << endl;
        }else{
            cout << "Using Unix/Linux ping command syntax" << endl;
            cout << "For more info: man ping" << endl;
        }
    }
    
    void executeScan(const string& target) override {
        int choice;
        do {
            displayMenu();
            cout << "Enter your choice: ";
            cin >> choice;
            switch (choice) {
                case 1:
                    pingBasic(target);
                    break;
                case 2: {
                    int count;
                    cout << "Enter number of packets to send: ";
                    cin >> count;
                    pingCount(target, count);
                    break;
                }
                case 3:
                    pingContinuous(target);
                    break;
                case 4: {
                    int packetSize;
                    cout << "Enter packet size in bytes: ";
                    cin >> packetSize;
                    pingSize(target, packetSize);
                    break;
                }
                case 5: {
                    int timeoutSec;
                    cout << "Enter timeout in seconds: ";
                    cin >> timeoutSec;
                    pingTimeout(target, timeoutSec);
                    break;
                }
                case 6:
                    pingHelp();
                    break;
                case 7:
                    cout << "Exiting Ping Options Menu." << endl;
                    break;
                default:
                    cout << "Invalid choice. Please try again." << endl;
            }
        } while (choice != 7);
    }   
};

// Derived class for Ping Sweep strategy
class PingSweepStrategy : public ScannerStrategy {
protected:
    string operatingSystem;
    string targetRange;
    vector<string> activeHosts;
    mutex hostMutex; 
    shared_ptr<ScanDatabase> database;
public:
    PingSweepStrategy(const string& os, shared_ptr<ScanDatabase> db) 
        : operatingSystem(os), database(db) {}
    
    void executeScan(const string& targetRange) override {
        this->targetRange = targetRange;
        int start, end;
        cout << "Enter start of range (last octet): ";
        cin >> start;
        cout << "Enter end of range (last octet): ";
        cin >> end;

        cout << "Scanning IPs from " << targetRange << start << " to " << targetRange << end << "...\n";

        vector<thread> threads;

        for (int i = start; i <= end; ++i) {
            string ip = targetRange + to_string(i);
            
            // Add host to database
            Host host(ip);
            database->addHost(host);

            // Launch a thread for each IP
            threads.emplace_back([this, ip]() {
                string command;

                if(operatingSystem == "Windows")
                    command = "ping -n 1 -w 1000 " + ip + " > nul 2>&1";
                else
                    command = "ping -c 1 -W 1 " + ip + " > /dev/null 2>&1";

                int result = system(command.c_str());
                if (result == 0) {
                    lock_guard<mutex> lock(this->hostMutex);
                    activeHosts.push_back(ip);
                    
                    // Update host status in database
                    Host activeHost(ip);
                    activeHost.setActive(true);
                    database->addHost(activeHost);
                }
            });
        }

        // Wait for all threads to finish
        for (auto &th : threads)
            th.join();

        // Display results
        cout << "Ping Sweep completed.\n";
        if (activeHosts.empty())
            cout << "No active hosts found.\n";
        else {
            cout << "Active hosts:\n";
            for (const auto &host : activeHosts)
                cout << host << "\n";
        }
        
        // Scan common ports for active hosts
        cout << "\nScanning common ports for active hosts..." << endl;
        CommonPortScanner portScanner;
        for (const auto& hostIP : activeHosts) {
            vector<Port> openPorts = portScanner.scanCommonPorts(hostIP);
            if (!openPorts.empty()) {
                database->updateHostPorts(hostIP, openPorts);
            }
        }
    }

    const vector<string>& getActiveHosts() const { return activeHosts; }
    virtual ~PingSweepStrategy() = default;
};

// Derived class for Ping Utility scanning
class PingUtility : public NetworkScanner {
private:
    string target;
    unique_ptr<PingUtilityStrategy> strategy;
    
public:
    PingUtility(const string& t, shared_ptr<ScanDatabase> db) 
        : NetworkScanner(db), target(t) {
        strategy = make_unique<PingUtilityStrategy>(operatingSystem);
    }
    
    void scan() override {
        cout << "Performing Ping Scan..." << endl;
        strategy->executeScan(target);
    }
    
    void displayResults() override {
        cout << "Ping Scan completed for target: " << target << endl;
    }   
};

// Derived class for Ping Sweep
class PingSweep : public NetworkScanner {
private:
    string targetRange;
    unique_ptr<PingSweepStrategy> strategy;
    
public:
    PingSweep(const string& range, shared_ptr<ScanDatabase> db) 
        : NetworkScanner(db), targetRange(range) {
        strategy = make_unique<PingSweepStrategy>(operatingSystem, database);
    }
    
    void scan() override {
        strategy->executeScan(targetRange);
    }
    
    void displayResults() override {
        if(strategy->getActiveHosts().empty()) {
            cout << "No active hosts found in the range: " << targetRange << endl;
            return;
        } else { 
            cout << "Ping Sweep completed. Active hosts found:" << endl;
            for(const auto& host : strategy->getActiveHosts()) {
                cout << host << endl;
            }
        }
    }   
};

// Derived Strategy class for Custom scanning
class CustomScanStrategy : public ScannerStrategy {
private:
    string operatingSystem;
public:
    CustomScanStrategy(const string& os) : operatingSystem(os) {}

    void displayMenu() {
        cout << "\nCustom Scan Options Menu:" << endl;
        cout << "1. Traceroute" << endl;
        cout << "2. DNS Lookup" << endl;
        cout << "3. Whois Lookup" << endl;
        cout << "4. Detect TTL/OS" << endl;
        cout << "5. Help" << endl;
        cout << "6. Exit" << endl;
    }

    void traceroute(const string& target) {
        cout << "Executing traceroute on: " << target << endl;
        string command;
        if (operatingSystem == "Windows")
            command = "tracert " + target;
        else
            command = "traceroute " + target;
        system(command.c_str());
    }

    void dnsLookup(const string& target) {
        cout << "Executing DNS Lookup for: " << target << endl;
        string command;
        if (operatingSystem == "Windows")
            command = "nslookup " + target;
        else
            command = "dig " + target;
        system(command.c_str());
    }

    void whoisLookup(const string& target) {
        cout << "Executing Whois Lookup for: " << target << endl;
        string command = "whois " + target; 
        system(command.c_str());
    }

    void osDetect(const string& target) {
        cout << "Attempting OS Detection using TTL on: " << target << endl;
        string command;
        if (operatingSystem == "Windows")
            command = "ping -n 1 " + target;
        else
            command = "ping -c 1 " + target;
        system(command.c_str());
        cout << "Note: Check TTL in output (64=Linux, 128=Windows, 255=Unix)." << endl;
    }

    void helpMenu() {
        cout << "\nCustom Scan Help:" << endl;
        cout << "Traceroute → shows path to target host." << endl;
        cout << "DNS Lookup → resolves IP/domain names." << endl;
        cout << "Whois Lookup → gets domain registration info." << endl;
        cout << "OS Detection → guesses OS using TTL from ping reply." << endl;
    }

    void executeScan(const string& target) override {
        int choice;
        do {
            displayMenu();
            cout << "Enter your choice: ";
            cin >> choice;
            switch (choice) {
                case 1: traceroute(target); break;
                case 2: dnsLookup(target); break;
                case 3: whoisLookup(target); break;
                case 4: osDetect(target); break;
                case 5: helpMenu(); break;
                case 6: cout << "Exiting Custom Scan Options." << endl; break;
                default: cout << "Invalid choice. Try again." << endl;
            }
        } while (choice != 6);
    }
};

// Derived class for Custom scanning
class CustomScanner : public NetworkScanner {
private:
    string target;
    unique_ptr<CustomScanStrategy> strategy;
public:
    CustomScanner(const string& t, shared_ptr<ScanDatabase> db) 
        : NetworkScanner(db), target(t) {
        strategy = make_unique<CustomScanStrategy>(operatingSystem);
    }

    void scan() override {
        cout << "Performing Custom Scan..." << endl;
        strategy->executeScan(target);
    }

    void displayResults() override {
        cout << "Custom Scan completed for target: " << target << endl;
    }
};

// Strategy for TCP Port Scanning
class TCPPortScanStrategy : public ScannerStrategy {
private:
    string target;
    int startPort, endPort;
    vector<int> openPorts;
    mutex portMutex;
    shared_ptr<ScanDatabase> database;

public:
    TCPPortScanStrategy(const string& target, int start, int end, shared_ptr<ScanDatabase> db)
        : target(target), startPort(start), endPort(end), database(db) {}

    void scanPort(int port) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) return;

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(target.c_str());

        // Set timeout
        struct timeval tv;
        tv.tv_sec = 1;  
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);

        int result = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
        if (result == 0) {
            lock_guard<mutex> lock(portMutex);
            openPorts.push_back(port);
            
            
            Port openPort(port);
            openPort.setOpen(true);
            vector<Port> ports = {openPort};
            database->updateHostPorts(target, ports);
        }
        close(sockfd);
    }

    void executeScan(const string& targetInput) override {
        cout << "Starting TCP Port Scan on " << target << " from port "
             << startPort << " to " << endPort << "...\n";

        vector<thread> threads;
        for (int port = startPort; port <= endPort; ++port) {
            threads.emplace_back(&TCPPortScanStrategy::scanPort, this, port);
        }

        for (auto& t : threads) t.join();

        cout << "TCP Port Scan Completed.\n";
        if (openPorts.empty())
            cout << "No open ports found.\n";
        else {
            cout << "Open Ports:\n";
            for (int p : openPorts) cout << "Port " << p << " is OPEN\n";  
        }
    }
};

// Derived class for TCP Port Scanning
class TCPPortScanner : public NetworkScanner {
private:
    string target;
    unique_ptr<TCPPortScanStrategy> strategy;

public:
    TCPPortScanner(const string& t, int start, int end, shared_ptr<ScanDatabase> db) 
        : NetworkScanner(db), target(t) {
        strategy = make_unique<TCPPortScanStrategy>(t, start, end, database);
    }

    void scan() override {
        strategy->executeScan(target);
    }

    void displayResults() override {
        cout << "TCP Port Scan completed for target: " << target << endl;
    }
};

// Interface class for user interaction and program execution
class UserInterface {
protected:
    unique_ptr<NetworkScanner> scanner;
    shared_ptr<ScanDatabase> database;
    int choice;
    
public:
    UserInterface() {
        database = make_shared<ScanDatabase>();
    }
    
    void start() {
        cout << "==========================================" << endl;
        cout << "       NETWORK SCANNER WITH DATABASE" << endl;
        cout << "==========================================" << endl;
        cout << "1. Ping Utility" << endl;
        cout << "2. Ping Sweep (Host Discovery + Common Ports)" << endl;
        cout << "3. TCP Port Scan" << endl;
        cout << "4. Custom Scan" << endl;
        cout << "5. Display Current Results" << endl;
        cout << "6. Save Results to Text File" << endl;
        cout << "7. View Scan History" << endl;
        cout << "8. View Session Details" << endl;
        cout << "9. Exit" << endl;
        
        cout << "Enter your choice: ";
        cin >> choice;
    }
    
    void execute() {
        string target;
        switch(choice) {
            case 1:
                database->startNewSession();
                cout << "Enter target IP address or hostname: ";
                cin >> target;
                scanner = make_unique<PingUtility>(target, database);
                scanner->scan();
                scanner->displayResults();
                database->endSession();
                break;
            case 2:
                cout << "Enter target IP range (e.g., 192.168.1.): ";
                cin >> target;
                database->startNewSession(target);
                scanner = make_unique<PingSweep>(target, database);
                scanner->scan();
                scanner->displayResults();
                database->endSession();
                break;
            case 3: 
                int startPort, endPort;
                cout << "Enter target IP address: ";
                cin >> target;
                cout << "Enter start port: ";
                cin >> startPort;
                cout << "Enter end port: ";
                cin >> endPort;
                database->startNewSession(target);
                scanner = make_unique<TCPPortScanner>(target, startPort, endPort, database);
                scanner->scan();
                scanner->displayResults();
                database->endSession();
                break;
            case 4:
                database->startNewSession();
                cout << "Enter target IP address or hostname: ";
                cin >> target;
                scanner = make_unique<CustomScanner>(target, database);
                scanner->scan();
                scanner->displayResults();
                database->endSession();
                break;      
            case 5:
                database->displayResults();
                break;
            case 6:
                database->saveToFile();
                break;
            case 7:
                database->displayHistory();
                break;
            case 8:
                int sessionId;
                cout << "Enter session ID to view: ";
                cin >> sessionId;
                database->displaySessionDetails(sessionId);
                break;
            case 9:
                cout << "Exiting program." << endl;
                break;
            default:
                cout << "Invalid choice. Please try again." << endl;
        }
    }
    
    bool shouldContinue() const {
        return choice != 9;
    }
};

// Main function
int main() {
    UserInterface ui;
    
    do {
        ui.start();
        ui.execute();
        if (ui.shouldContinue()) {
            cout << "\nPress Enter to continue...";
            cin.ignore();
            cin.get();
        }
    } while (ui.shouldContinue());
    
    return 0;
}