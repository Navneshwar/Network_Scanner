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
class UserInterface;




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
public:
    NetworkScanner() {
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
public:
    PingSweepStrategy(const string& os) : operatingSystem(os) {}
    
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
    PingUtility(const string& t) : target(t) {
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
    PingSweep(const string& range) : targetRange(range) {
        strategy = make_unique<PingSweepStrategy>(operatingSystem);
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
    CustomScanner(const string& t) : target(t) {
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

public:
    TCPPortScanStrategy(const string& target, int start, int end)
        : target(target), startPort(start), endPort(end) {}

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
    TCPPortScanner(const string& t, int start, int end) : target(t) {
        strategy = make_unique<TCPPortScanStrategy>(t, start, end);
    }

    void scan() override {
        strategy->executeScan(target);
    }

    void displayResults() override {
        cout << "TCP Port Scan completed for target: " << target <<endl;
}
};

// Interface class for user interaction and program execution
class UserInterface {
protected:
    unique_ptr<NetworkScanner> scanner;
    int choice;
public:
    void start() {
        cout << "Welcome to Network Scanner" << endl;
        cout << "1. Ping Utility" << endl;
        cout << "2. Ping Sweep" << endl;
        cout << "3. TCP Port Scan" << endl;
        cout << "4. Custom Scan" << endl;
        cout << "5. Exit" << endl;
        
        cout << "Enter your choice: ";
        cin >> choice;
    }
    
    void execute() {
        string target;
        switch(choice) {
            case 1:
                cout << "Enter target IP address or hostname: ";
                cin >> target;
                scanner = make_unique<PingUtility>(target);
                scanner->scan();
                scanner->displayResults();
                break;
            case 2:
                cout << "Enter target IP range (e.g., 192.168.1.): ";
                cin >> target;
                scanner = make_unique<PingSweep>(target);
                scanner->scan();
                scanner->displayResults();
                break;
            case 3: 
                int startPort, endPort;
                cout << "Enter target IP address: ";
                cin >> target;
                cout << "Enter start port: ";
                cin >> startPort;
                cout << "Enter end port: ";
                cin >> endPort;
                scanner = make_unique<TCPPortScanner>(target, startPort, endPort);
                scanner->scan();
                scanner->displayResults();
                break;
            case 4:
                cout << "Enter target IP address or hostname: ";
                cin >> target;
                scanner = make_unique<CustomScanner>(target);
                scanner->scan();
                scanner->displayResults();
                break;      
            case 5:
                cout << "Exiting program." << endl;
                break;

            default:
                cout << "Invalid choice. Exiting." << endl;
        }
    }
};

// Main function
int main() {
    UserInterface ui;
    ui.start();
    ui.execute();
    
    return 0;
}
//concepts used: inheritance, polymorphism, strategy pattern, threading, mutex for thread safety, system calls for pinging, unique_ptr for memory management.
//C++14 standard features are used.
//The code is modular and can be extended with additional scanning strategies in the future.
// Main Inheritance Map:
// 
// ScannerStrategy (Interface)
// ├── PingUtilityStrategy
// ├── PingSweepStrategy
// ├── CustomScanStrategy
// └── TCPPortScanStrategy
//
// NetworkScanner (Abstract Base Class)
// ├── PingUtility (uses PingUtilityStrategy)
// ├── PingSweep (uses PingSweepStrategy)
// ├── CustomScanner (uses CustomScanStrategy)
// └── TCPPortScanner (uses TCPPortScanStrategy)
//
// UserInterface (Manages the program flow and uses NetworkScanner hierarchy)
//
//Class Relationships:
// - UserInterface creates and uses NetworkScanner derived classes based on user input. 
// - Each NetworkScanner derived class uses a specific ScannerStrategy derived class to perform its scanning tasks.
// - Strategies encapsulate the scanning algorithms and can be swapped easily. 
// - Mutex is used in PingSweepStrategy and TCPPortScanStrategy to ensure thread-safe access to shared resources (activeHosts and openPorts).
// - Threads are used in PingSweepStrategy and TCPPortScanStrategy to perform concurrent scanning for efficiency.
// - System calls are used to execute ping, traceroute, nslookup, whois, and port scanning commands.
// - Unique pointers (unique_ptr) are used for automatic memory management of strategy objects.
// - The program is designed to be modular and extensible, allowing for easy addition of new scanning strategies in the future.
// - The code adheres to the C++14 standard, utilizing features such as make_unique and lambda expressions.
// - The program is cross-platform, with specific command syntax for Windows and Unix-like systems handled in the strategy classes.
// - The main function initializes the UserInterface, which manages user interaction and orchestrates the scanning process.
// - The program includes error handling for invalid user inputs and system command execution results.


