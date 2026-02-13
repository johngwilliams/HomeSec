using HomeSec.Core.Models;

namespace HomeSec.Core.Services;

/// <summary>
/// Classifies network devices into user-friendly categories based on
/// open ports, vendor info, hostname, and other heuristics.
/// </summary>
public sealed class DeviceClassifier
{
    public void ClassifyAll(IEnumerable<NetworkDevice> devices)
    {
        foreach (var device in devices)
            Classify(device);
    }

    public void Classify(NetworkDevice device)
    {
        // Resolve vendor from MAC
        device.Vendor ??= MacVendorLookup.GetVendor(device.MacAddress);

        // Classify using a priority chain of heuristics
        device.Category = ClassifyByGateway(device)
                          ?? ClassifyByVendor(device)
                          ?? ClassifyByHostname(device)
                          ?? ClassifyByPorts(device)
                          ?? DeviceCategory.Unknown;

        // Infer OS where possible
        device.OperatingSystem ??= InferOperatingSystem(device);
    }

    private static DeviceCategory? ClassifyByGateway(NetworkDevice device)
    {
        return device.IsGateway ? DeviceCategory.Router : null;
    }

    private static DeviceCategory? ClassifyByVendor(NetworkDevice device)
    {
        if (device.Vendor is null) return null;
        string vendor = device.Vendor.ToLowerInvariant();

        // Routers / networking
        if (IsMatch(vendor, "netgear", "linksys", "tp-link", "d-link",
                "cisco", "ubiquiti", "asus", "belkin"))
        {
            // Could be a router or access point. If it's the gateway, already handled.
            // If it has port 80/443 open, likely a network device.
            return DeviceCategory.Router;
        }

        // Smart speakers
        if (IsMatch(vendor, "amazon echo", "sonos"))
            return DeviceCategory.SmartSpeaker;

        if (IsMatch(vendor, "amazon"))
            return DeviceCategory.SmartSpeaker; // Fire TV / Echo

        if (IsMatch(vendor, "google nest", "nest"))
            return DeviceCategory.IoTDevice;

        // Game consoles
        if (IsMatch(vendor, "nintendo"))
            return DeviceCategory.GameConsole;
        if (IsMatch(vendor, "playstation", "sony playstation"))
            return DeviceCategory.GameConsole;
        if (IsMatch(vendor, "xbox", "microsoft xbox"))
            return DeviceCategory.GameConsole;

        // Smart TV & streaming
        if (IsMatch(vendor, "roku"))
            return DeviceCategory.SmartTV;
        if (IsMatch(vendor, "lg electronics"))
            return DeviceCategory.SmartTV;
        if (IsMatch(vendor, "samsung smartthings"))
            return DeviceCategory.IoTDevice;

        // Printers
        if (IsMatch(vendor, "brother", "epson", "canon"))
            return DeviceCategory.Printer;
        if (IsMatch(vendor, "hp"))
        {
            // HP makes both PCs and printers — check for print ports
            return device.OpenPorts.Any(p => p.Port is 631 or 9100)
                ? DeviceCategory.Printer
                : DeviceCategory.Computer;
        }

        // IoT / smart home
        if (IsMatch(vendor, "philips hue", "ring", "wyze"))
            return DeviceCategory.IoTDevice;

        // Cameras
        if (vendor.Contains("camera") || vendor.Contains("hikvision") || vendor.Contains("dahua"))
            return DeviceCategory.SecurityCamera;

        // Raspberry Pi
        if (IsMatch(vendor, "raspberry pi"))
            return DeviceCategory.Server;

        // Apple devices
        if (IsMatch(vendor, "apple"))
            return null; // Apple makes phones, tablets, computers — disambiguate by ports

        // Samsung
        if (IsMatch(vendor, "samsung"))
            return null; // Could be phone or TV — disambiguate by ports

        // PC manufacturers
        if (IsMatch(vendor, "dell", "lenovo", "intel", "realtek", "microsoft"))
            return DeviceCategory.Computer;

        // Google (could be Chromecast, phone, etc.)
        if (IsMatch(vendor, "google"))
            return DeviceCategory.IoTDevice;

        return null;
    }

    private static DeviceCategory? ClassifyByHostname(NetworkDevice device)
    {
        if (device.Hostname is null) return null;
        string host = device.Hostname.ToLowerInvariant();

        if (host.Contains("iphone") || host.Contains("android") || host.Contains("pixel") ||
            host.Contains("galaxy") && !host.Contains("tab"))
            return DeviceCategory.Phone;

        if (host.Contains("ipad") || host.Contains("tab") || host.Contains("tablet"))
            return DeviceCategory.Tablet;

        if (host.Contains("macbook") || host.Contains("desktop") || host.Contains("laptop") ||
            host.Contains("-pc") || host.Contains("workstation"))
            return DeviceCategory.Computer;

        if (host.Contains("nas") || host.Contains("synology") || host.Contains("qnap"))
            return DeviceCategory.NAS;

        if (host.Contains("printer") || host.Contains("print"))
            return DeviceCategory.Printer;

        if (host.Contains("camera") || host.Contains("cam"))
            return DeviceCategory.SecurityCamera;

        if (host.Contains("tv") || host.Contains("roku") || host.Contains("firestick"))
            return DeviceCategory.SmartTV;

        return null;
    }

    private static DeviceCategory? ClassifyByPorts(NetworkDevice device)
    {
        var ports = device.OpenPorts.Select(p => p.Port).ToHashSet();

        // Printer: IPP or raw print
        if (ports.Contains(631) || ports.Contains(9100))
            return DeviceCategory.Printer;

        // Camera: RTSP streaming
        if (ports.Contains(554))
            return DeviceCategory.SecurityCamera;

        // NAS: SMB + web admin
        if (ports.Contains(445) && (ports.Contains(80) || ports.Contains(5000)))
            return DeviceCategory.NAS;

        // Server: SSH + HTTP
        if (ports.Contains(22) && ports.Contains(80))
            return DeviceCategory.Server;

        // Computer: RDP or SMB
        if (ports.Contains(3389) || ports.Contains(445))
            return DeviceCategory.Computer;

        return null;
    }

    private static string? InferOperatingSystem(NetworkDevice device)
    {
        var ports = device.OpenPorts.Select(p => p.Port).ToHashSet();
        string? host = device.Hostname?.ToLowerInvariant();
        string? vendor = device.Vendor?.ToLowerInvariant();

        if (host?.Contains("iphone") == true || host?.Contains("ipad") == true ||
            host?.Contains("macbook") == true)
            return "Apple (iOS/macOS)";

        if (host?.Contains("android") == true)
            return "Android";

        if (ports.Contains(3389) || ports.Contains(135))
            return "Windows";

        if (ports.Contains(22) && !ports.Contains(3389) && vendor != null &&
            !vendor.Contains("cisco") && !vendor.Contains("ubiquiti"))
            return "Linux / Unix";

        if (ports.Contains(548))
            return "macOS";

        return null;
    }

    private static bool IsMatch(string value, params string[] candidates) =>
        candidates.Any(c => value.Contains(c));
}
