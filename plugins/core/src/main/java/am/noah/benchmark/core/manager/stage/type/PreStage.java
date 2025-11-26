package am.noah.benchmark.core.manager.stage.type;

import am.noah.benchmark.core.Benchmark;
import am.noah.benchmark.core.manager.stage.StageManager;
import am.noah.benchmark.core.util.Bridge;
import oshi.SystemInfo;
import oshi.hardware.CentralProcessor;
import oshi.hardware.GlobalMemory;
import oshi.hardware.HWDiskStore;
import oshi.hardware.HardwareAbstractionLayer;
import oshi.software.os.OperatingSystem;
import oshi.util.FormatUtil;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class PreStage extends StageManager {

    SystemInfo systemInfo;
    private String singleThreadScore = "(pending)";
    private String multiThreadScore = "(pending)";
    private String provider = "Unable to retrieve";
    private String location = "Unable to retrieve";
    private String geolocation = "Unable to retrieve";
    private String domain = "Unknown";
    private String externalIP = "Unable to retrieve";
    private String systemIP = "Unable to retrieve";
    private String vmStatus = "No";
    private String storageInfo = "Unable to retrieve";
    private String storageUsage = "Unable to retrieve";
    private String cpuModel = "Unable to retrieve";
    private String osInfo = "Unable to retrieve";
    private long totalMemory = 0;
    private long totalSwap = 0;
    private int physicalCores = 0;
    private int logicalCores = 0;
    private String microarchitecture = "Unknown";
    private String cpuIdentification = "Unknown";

    /**
     * Initialize the PreStage object.
     */
    public PreStage(Benchmark benchmark) {
        setBenchmark(benchmark);

        systemInfo = new SystemInfo();
        // Get a warning to pop up out of the way (if it happens at all).
        systemInfo.getOperatingSystem();

        // Pre-collect all system information
        collectSystemInformation();

        benchmark.getBridge().log("");
        benchmark.getBridge().log("Pausing for 10 seconds to let CPU usage normalize.");
        benchmark.getBridge().log("");

        // Start a new Timer to end the stage.
        benchmark.getTimerManager().newTimer(benchmark, 10);
    }

    /**
     * Collect all system information upfront
     */
    private void collectSystemInformation() {
        Bridge bridge = getBenchmark().getBridge();
        HardwareAbstractionLayer hardware = systemInfo.getHardware();
        OperatingSystem os = systemInfo.getOperatingSystem();

        // Collect OS information
        osInfo = os.toString();

        // Collect VM information
        vmStatus = detectVirtualization(hardware, os);

        // Collect storage information
        collectStorageInformation(hardware);

        // Collect memory information
        GlobalMemory memory = hardware.getMemory();
        totalMemory = memory.getTotal();
        totalSwap = memory.getVirtualMemory().getSwapTotal();

        // Collect CPU information
        CentralProcessor processor = hardware.getProcessor();
        cpuModel = getRealCPUModel(processor);
        physicalCores = processor.getPhysicalProcessorCount();
        logicalCores = processor.getLogicalProcessorCount();
        microarchitecture = processor.getProcessorIdentifier().getMicroarchitecture();
        cpuIdentification = processor.getProcessorIdentifier().getIdentifier();

        // Collect network information in background thread to avoid blocking
        new Thread(() -> {
            collectNetworkInformation(bridge);
        }).start();
    }

    /**
     * Collect network information
     */
    private void collectNetworkInformation(Bridge bridge) {
        provider = getWithFallbacks(
            "https://ipapi.co/org/",
            "https://ipinfo.io/org/",
            "https://api.ip.sb/org/",
            "Unable to retrieve"
        );
        
        String city = getWithFallbacks(
            "https://ipapi.co/city/",
            "https://ipinfo.io/city/",
            "https://api.ip.sb/city/",
            "Unknown"
        );
        
        String region = getWithFallbacks(
            "https://ipapi.co/region/",
            "https://ipinfo.io/region/",
            "https://api.ip.sb/region/",
            "Unknown"
        );
        
        String country = getWithFallbacks(
            "https://ipapi.co/country_name/",
            "https://ipinfo.io/country/",
            "https://api.ip.sb/country/",
            "Unknown"
        );
        
        location = city + ", " + region + ", " + country;
        
        geolocation = getWithFallbacks(
            "https://ipapi.co/latlong/",
            "https://ipinfo.io/loc/",
            "https://api.ip.sb/geoip/",
            "Unable to retrieve"
        );

        externalIP = getWithFallbacks(
            "http://checkip.amazonaws.com",
            "https://api.ipify.org",
            "https://icanhazip.com",
            "Unable to retrieve"
        );

        systemIP = collectSystemIP();

        if (!externalIP.equals("Unable to retrieve")) {
            domain = getDomainFromIP(externalIP);
        }
    }

    /**
     * Collect storage information
     */
    private void collectStorageInformation(HardwareAbstractionLayer hardware) {
        try {
            List<HWDiskStore> disks = hardware.getDiskStores();
            if (!disks.isEmpty()) {
                StringBuilder storageBuilder = new StringBuilder();
                for (HWDiskStore disk : disks) {
                    if (disk.getSize() > 0) {
                        storageBuilder.append(disk.getModel()).append(" (").append(FormatUtil.formatBytes(disk.getSize())).append("), ");
                    }
                }
                if (storageBuilder.length() > 2) {
                    storageBuilder.setLength(storageBuilder.length() - 2);
                }
                storageInfo = storageBuilder.toString();

                // Calculate storage usage
                try {
                    java.io.File[] roots = java.io.File.listRoots();
                    if (roots != null && roots.length > 0) {
                        long totalSpace = 0;
                        long freeSpace = 0;
                        for (java.io.File root : roots) {
                            totalSpace += root.getTotalSpace();
                            freeSpace += root.getFreeSpace();
                        }
                        long usedSpace = totalSpace - freeSpace;
                        storageUsage = FormatUtil.formatBytes(usedSpace) + " used, " + 
                                      FormatUtil.formatBytes(freeSpace) + " free, " + 
                                      FormatUtil.formatBytes(totalSpace) + " total";
                    }
                } catch (Exception e) {
                    storageUsage = "Usage information unavailable";
                }
            } else {
                storageInfo = "No disks detected";
            }
        } catch (Exception e) {
            storageInfo = "Unable to retrieve storage information";
            storageUsage = "Unable to retrieve usage information";
        }
    }

    /**
     * When the current stage ends we need to output all of the hardware information and switch to the SingleStage.
     */
    @Override
    public void endStage() {
        Bridge bridge = getBenchmark().getBridge();
        Runtime runtime = Runtime.getRuntime();

        /*
         * It's also important to know what start up flags the server is using.
         * Through the use of this method we can find these flags.
         */
        RuntimeMXBean runtimeBean = ManagementFactory.getRuntimeMXBean();
        StringBuilder startupFlags = new StringBuilder();

        // Assemble all of the individual flags into one String.
        for (String flag : runtimeBean.getInputArguments()) {
            startupFlags.append(flag).append(" ");
        }

        /*
         * What plugin version is being used and what server version/type?
         * This may affect results, so we should track it.
         */
        bridge.log("");
        bridge.log("Benchmark Version: " + getBenchmark().getVersion() + " (Updated by ShadowGaming100, made by; amnoah)");
        bridge.log("Server Version: " + getBenchmark().getServerVersion());
        bridge.log("Startup Flags: " + startupFlags);
        bridge.log("");

        // Display provider and location information
        displayProviderInformation(bridge);

        // Display node specifications
        displayNodeSpecifications(bridge);

        // Display IP information
        displayIPInformation(bridge);

        // Spacing ;)
        bridge.log("");

        getBenchmark().setStageManager(new SingleStage(getBenchmark()));
    }

    /**
     * Display provider and location information
     */
    private void displayProviderInformation(Bridge bridge) {
        bridge.log("-->Provider & Location");
        bridge.log("Provider: " + provider);
        bridge.log("Location: " + location);
        bridge.log("Possible geolocation: " + geolocation);
        bridge.log("");
    }

    /**
     * Display node specifications
     */
    private void displayNodeSpecifications(Bridge bridge) {
        bridge.log("-->Node Specifications");
        bridge.log("OS: " + osInfo);
        bridge.log("VM: " + vmStatus);
        bridge.log("Storage: " + storageInfo);
        bridge.log("Storage Usage: " + storageUsage);
        bridge.log("Memory: " + FormatUtil.formatBytes(totalMemory));
        bridge.log("Swap: " + FormatUtil.formatBytes(totalSwap));
        bridge.log("CPU: " + cpuModel);
        bridge.log("CPU Cores count: " + physicalCores);
        bridge.log("CPU Thread Count: " + logicalCores);
        bridge.log("Microarchitecture: " + microarchitecture);
        bridge.log("Identification: " + cpuIdentification);
        bridge.log("Benchmark scores: Single: " + singleThreadScore + ", Multiple: " + multiThreadScore);
        bridge.log("");
    }

    /**
     * Display IP address information
     */
    private void displayIPInformation(Bridge bridge) {
        bridge.log("-->Node IP:");
        bridge.log("Domain: " + domain);
        bridge.log("System IP: " + systemIP);
        bridge.log("External IP: " + externalIP);
        bridge.log("");
    }

    /**
     * Helper method to try multiple APIs with fallbacks
     */
    private String getWithFallbacks(String... urls) {
        for (int i = 0; i < urls.length - 1; i++) {
            try {
                URL url = new URL(urls[i]);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(3000);
                conn.setReadTimeout(3000);
                conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Benchmark Tool)");
                
                int responseCode = conn.getResponseCode();
                if (responseCode == 200) {
                    java.io.BufferedReader in = new java.io.BufferedReader(new java.io.InputStreamReader(conn.getInputStream()));
                    String result = in.readLine();
                    in.close();
                    
                    if (result != null && !result.trim().isEmpty() && 
                        !result.contains("Undefined") && !result.contains("error")) {
                        return result.trim();
                    }
                }
            } catch (Exception e) {
                // Continue to next fallback
            }
        }
        return urls[urls.length - 1];
    }

    /**
     * Enhanced virtualization detection
     */
    private String detectVirtualization(HardwareAbstractionLayer hardware, OperatingSystem os) {
        List<String> vmIndicators = new ArrayList<>();
        
        // Check system manufacturer and model
        String manufacturer = hardware.getComputerSystem().getManufacturer();
        String model = hardware.getComputerSystem().getModel();
        
        if (manufacturer != null) {
            manufacturer = manufacturer.toLowerCase();
            model = model != null ? model.toLowerCase() : "";
            
            if (manufacturer.contains("vmware") || model.contains("vmware")) vmIndicators.add("VMware");
            if ((manufacturer.contains("microsoft") && model.contains("virtual")) || model.contains("hyper-v")) vmIndicators.add("Hyper-V");
            if (manufacturer.contains("innotek") || manufacturer.contains("oracle") || model.contains("virtualbox")) vmIndicators.add("VirtualBox");
            if (manufacturer.contains("red hat") || manufacturer.contains("qemu") || model.contains("kvm") || model.contains("qemu")) vmIndicators.add("KVM/QEMU");
            if (manufacturer.contains("xen") || model.contains("xen")) vmIndicators.add("Xen");
            if (manufacturer.contains("amazon") || model.contains("amazon")) vmIndicators.add("AWS EC2");
            if (manufacturer.contains("google") || model.contains("google")) vmIndicators.add("Google Cloud");
            if (manufacturer.contains("digitalocean") || model.contains("digitalocean")) vmIndicators.add("DigitalOcean");
        }
        
        // Check processor features
        String processorName = hardware.getProcessor().toString().toLowerCase();
        if (processorName.contains("vmware") || processorName.contains("virtual") || 
            processorName.contains("qemu") || processorName.contains("kvm") ||
            processorName.contains("hypervisor")) {
            vmIndicators.add("Virtualized CPU");
        }
        
        // Check DMI information (if available on Linux)
        if (os.getFamily().toLowerCase().contains("linux")) {
            try {
                // Check product name
                Process process = Runtime.getRuntime().exec("cat /sys/class/dmi/id/product_name 2>/dev/null");
                java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(process.getInputStream()));
                String dmiProduct = reader.readLine();
                reader.close();
                
                if (dmiProduct != null) {
                    dmiProduct = dmiProduct.toLowerCase();
                    if (dmiProduct.contains("vmware")) vmIndicators.add("VMware");
                    if (dmiProduct.contains("virtual")) vmIndicators.add("Virtual Machine");
                    if (dmiProduct.contains("kvm")) vmIndicators.add("KVM");
                    if (dmiProduct.contains("amazon")) vmIndicators.add("AWS");
                    if (dmiProduct.contains("google")) vmIndicators.add("Google Cloud");
                }
                
                // Check system vendor
                process = Runtime.getRuntime().exec("cat /sys/class/dmi/id/sys_vendor 2>/dev/null");
                reader = new java.io.BufferedReader(new java.io.InputStreamReader(process.getInputStream()));
                String dmiVendor = reader.readLine();
                reader.close();
                
                if (dmiVendor != null) {
                    dmiVendor = dmiVendor.toLowerCase();
                    if (dmiVendor.contains("vmware")) vmIndicators.add("VMware");
                    if (dmiVendor.contains("microsoft")) vmIndicators.add("Hyper-V");
                    if (dmiVendor.contains("innotek") || dmiVendor.contains("oracle")) vmIndicators.add("VirtualBox");
                    if (dmiVendor.contains("red hat") || dmiVendor.contains("qemu")) vmIndicators.add("KVM/QEMU");
                }
            } catch (Exception e) {
                // Ignore, DMI might not be available
            }
        }
        
        // Check for containerization (Docker, etc.)
        if (isContainerized()) {
            vmIndicators.add("Containerized");
        }
        
        if (!vmIndicators.isEmpty()) {
            return "Yes (" + String.join(", ", vmIndicators) + ")";
        }
        
        return "No (Physical)";
    }

    /**
     * Check if running in container
     */
    private boolean isContainerized() {
        try {
            // Check for .dockerenv file
            java.io.File dockerEnv = new java.io.File("/.dockerenv");
            if (dockerEnv.exists()) {
                return true;
            }
            
            // Check cgroup info
            Process process = Runtime.getRuntime().exec("cat /proc/1/cgroup 2>/dev/null");
            java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("docker") || line.contains("kubepods") || line.contains("containerd")) {
                    reader.close();
                    return true;
                }
            }
            reader.close();
        } catch (Exception e) {
            // Ignore errors
        }
        return false;
    }

    /**
     * Get the real CPU model, even when virtualized
     */
    private String getRealCPUModel(CentralProcessor processor) {
        String cpuName = processor.toString();
        String identifier = processor.getProcessorIdentifier().getIdentifier();
        
        // If we detect virtualization, try to get real CPU info
        if (cpuName.toLowerCase().contains("virtual") || cpuName.toLowerCase().contains("qemu") || 
            cpuName.toLowerCase().contains("kvm") || cpuName.toLowerCase().contains("vmware")) {
            
            // Try to detect underlying physical CPU
            String physicalCPU = detectPhysicalCPU();
            if (!physicalCPU.isEmpty()) {
                return physicalCPU + " [Virtualized: " + cpuName + "]";
            }
            
            // Try to get better info from processor identifier
            if (identifier != null && !identifier.contains("Unknown") && !identifier.contains("GenuineIntel")) {
                return identifier + " [Virtualized]";
            }
        }
        
        return cpuName;
    }

    /**
     * Attempt to detect the physical CPU behind virtualization
     */
    private String detectPhysicalCPU() {
        // Try to get CPU info from /proc/cpuinfo on Linux systems
        try {
            Process process = Runtime.getRuntime().exec("cat /proc/cpuinfo");
            java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(process.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("model name") || line.startsWith("cpu model") || line.startsWith("Processor")) {
                    String modelName = line.substring(line.indexOf(":") + 1).trim();
                    // Return the first model name found that isn't virtual
                    if (!modelName.toLowerCase().contains("virtual") && 
                        !modelName.toLowerCase().contains("qemu") &&
                        !modelName.toLowerCase().contains("kvm") && 
                        !modelName.toLowerCase().contains("vmware")) {
                        reader.close();
                        return modelName;
                    }
                }
            }
            reader.close();
        } catch (Exception e) {
            // Silently ignore exceptions
        }
        
        return "";
    }

    /**
     * Collect system IP addresses (renamed from getSystemIP to avoid duplicate)
     */
    private String collectSystemIP() {
        try {
            StringBuilder ips = new StringBuilder();
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                // Skip loopback and inactive interfaces
                if (iface.isLoopback() || !iface.isUp()) continue;
                
                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    // Only include IPv4 addresses for simplicity
                    if (addr.getHostAddress().contains(".")) {
                        if (ips.length() > 0) ips.append(", ");
                        ips.append(addr.getHostAddress());
                    }
                }
            }
            return ips.toString();
        } catch (Exception e) {
            try {
                return InetAddress.getLocalHost().getHostAddress();
            } catch (UnknownHostException ex) {
                return "Unable to retrieve";
            }
        }
    }

    /**
     * Get domain from IP using reverse DNS lookup
     */
    private String getDomainFromIP(String ip) {
        try {
            // Try reverse DNS lookup first
            InetAddress addr = InetAddress.getByName(ip);
            String hostname = addr.getCanonicalHostName();
            if (!hostname.equals(ip) && !hostname.contains("in-addr.arpa")) {
                return hostname;
            }
            
            // Try external service as fallback
            String domain = getWithFallbacks(
                "https://api.hackertarget.com/reverseiplookup/?q=" + ip,
                "https://api.ip.sb/reverse/" + ip,
                "Unknown"
            );
            
            // If the API returns multiple results, take the first one
            if (domain.contains("\n")) {
                domain = domain.split("\n")[0];
            }
            
            return domain;
        } catch (Exception e) {
            return "Unknown";
        }
    }

    // Methods to update scores for summary
    public void setSingleThreadScore(String score) {
        this.singleThreadScore = score;
    }

    public void setMultiThreadScore(String score) {
        this.multiThreadScore = score;
    }

    // Public getters for summary information
    public String getProvider() { return provider; }
    public String getLocation() { return location; }
    public String getGeolocation() { return geolocation; }
    public String getDomain() { return domain; }
    public String getExternalIP() { return externalIP; }
    public String getSystemIP() { return systemIP; }
    public String getVmStatus() { return vmStatus; }
    public String getStorageInfo() { return storageInfo; }
    public String getStorageUsage() { return storageUsage; }
    public String getCpuModel() { return cpuModel; }
    public String getOsInfo() { return osInfo; }
    public long getTotalMemory() { return totalMemory; }
    public long getTotalSwap() { return totalSwap; }
    public int getPhysicalCores() { return physicalCores; }
    public int getLogicalCores() { return logicalCores; }
    public String getMicroarchitecture() { return microarchitecture; }
    public String getCpuIdentification() { return cpuIdentification; }
    public String getSingleThreadScore() { return singleThreadScore; }
    public String getMultiThreadScore() { return multiThreadScore; }
}