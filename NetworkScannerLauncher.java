import java.io.*;
import java.util.Scanner;

public class NetworkScannerLauncher {
    private static final String CPP_EXECUTABLE = "./main"; // or "network_scanner.exe" on Windows
    private Scanner inputScanner;
    
    public NetworkScannerLauncher() {
        inputScanner = new Scanner(System.in);
    }
    
    public static void main(String[] args) {
        NetworkScannerLauncher launcher = new NetworkScannerLauncher();
        launcher.run();
    }
    
    public void run() {
        System.out.println("==========================================");
        System.out.println("   JAVA-C++ NETWORK SCANNER LAUNCHER");
        System.out.println("==========================================");
        
        // Check if executable exists
        if (!new File(CPP_EXECUTABLE).exists()) {
            System.out.println("Error: C++ executable '" + CPP_EXECUTABLE + "' not found!");
            System.out.println("Please make sure your compiled C++ program is named '" + CPP_EXECUTABLE + "'");
            return;
        }
        
        System.out.println("C++ executable found: " + CPP_EXECUTABLE);
        
        // Main interaction loop
        while (true) {
            displayMainMenu();
            int choice = getIntInput("Enter your choice: ");
            
            if (choice == 9) {
                System.out.println("Exiting Java launcher. Goodbye!");
                break;
            }
            
            executeCppProgram(choice);
            
            System.out.println("\nPress Enter to continue...");
            inputScanner.nextLine(); // Wait for user input
        }
        
        inputScanner.close();
    }
    
    private void displayMainMenu() {
        System.out.println("\n==========================================");
        System.out.println("       NETWORK SCANNER LAUNCHER");
        System.out.println("==========================================");
        System.out.println("1. Ping Utility");
        System.out.println("2. Ping Sweep (Host Discovery + Common Ports)");
        System.out.println("3. TCP Port Scan");
        System.out.println("4. Custom Scan");
        System.out.println("5. Display Current Results");
        System.out.println("6. Save Results to Text File");
        System.out.println("7. View Scan History");
        System.out.println("8. View Session Details");
        System.out.println("9. Exit");
    }
    
    private void executeCppProgram(int choice) {
        try {
            ProcessBuilder pb = new ProcessBuilder(CPP_EXECUTABLE);
            pb.redirectErrorStream(true);
            
            Process process = pb.start();
            
            // Thread to read output from C++ program
            Thread outputThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        System.out.println(line);
                    }
                } catch (IOException e) {
                    System.out.println("Error reading output: " + e.getMessage());
                }
            });
            
            // Thread to send input to C++ program
            Thread inputThread = new Thread(() -> {
                try (PrintWriter writer = new PrintWriter(process.getOutputStream())) {
                    // Send the initial choice
                    writer.println(choice);
                    writer.flush();
                    
                    // Handle additional input based on choice
                    handleAdditionalInput(writer, choice);
                    
                } catch (Exception e) {
                    System.out.println("Error handling input: " + e.getMessage());
                }
            });
            
            outputThread.start();
            inputThread.start();
            
            // Wait for threads to complete
            outputThread.join();
            inputThread.join();
            
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                System.out.println("C++ program exited with code: " + exitCode);
            }
            
        } catch (IOException | InterruptedException e) {
            System.out.println("Error executing C++ program: " + e.getMessage());
        }
    }
    
    private void handleAdditionalInput(PrintWriter writer, int choice) {
        switch (choice) {
            case 1: // Ping Utility
                String target = getStringInput("Enter target IP address or hostname: ");
                writer.println(target);
                writer.flush();
                break;
                
            case 2: // Ping Sweep
                String ipRange = getStringInput("Enter target IP range (e.g., 192.168.1.): ");
                writer.println(ipRange);
                writer.flush();
                break;
                
            case 3: // TCP Port Scan
                String tcpTarget = getStringInput("Enter target IP address: ");
                writer.println(tcpTarget);
                writer.flush();
                
                int startPort = getIntInput("Enter start port: ");
                writer.println(startPort);
                writer.flush();
                
                int endPort = getIntInput("Enter end port: ");
                writer.println(endPort);
                writer.flush();
                break;
                
            case 4: // Custom Scan
                String customTarget = getStringInput("Enter target IP address or hostname: ");
                writer.println(customTarget);
                writer.flush();
                break;
                
            case 8: // View Session Details
                int sessionId = getIntInput("Enter session ID to view: ");
                writer.println(sessionId);
                writer.flush();
                break;
                
            default:
                // For choices 5,6,7 no additional input needed
                break;
        }
    }
    
    private String getStringInput(String prompt) {
        System.out.print(prompt);
        return inputScanner.nextLine().trim();
    }
    
    private int getIntInput(String prompt) {
        while (true) {
            System.out.print(prompt);
            try {
                int value = inputScanner.nextInt();
                inputScanner.nextLine(); // Consume newline
                return value;
            } catch (Exception e) {
                System.out.println("Invalid input. Please enter a number.");
                inputScanner.nextLine(); // Clear invalid input
            }
        }
    }
}