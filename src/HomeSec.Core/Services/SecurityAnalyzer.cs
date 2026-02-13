using HomeSec.Core.Models;

namespace HomeSec.Core.Services;

/// <summary>
/// Analyzes discovered devices for common home-network security issues
/// and generates user-friendly findings with fix recommendations.
/// </summary>
public sealed class SecurityAnalyzer
{
    public void AnalyzeAll(IEnumerable<NetworkDevice> devices)
    {
        foreach (var device in devices)
            Analyze(device);
    }

    public void Analyze(NetworkDevice device)
    {
        device.Findings.Clear();

        CheckTelnetExposure(device);
        CheckFtpExposure(device);
        CheckSmbExposure(device);
        CheckRdpExposure(device);
        CheckVncExposure(device);
        CheckHttpAdminPanels(device);
        CheckUnencryptedMail(device);
        CheckUpnpExposure(device);
        CheckMqttExposure(device);
        CheckDatabaseExposure(device);
        CheckDefaultCameraStreams(device);
        CheckIoTDeviceSecurity(device);
        CheckRouterSecurity(device);
    }

    private static void CheckTelnetExposure(NetworkDevice device)
    {
        if (!HasPort(device, 23)) return;

        device.Findings.Add(new SecurityFinding
        {
            Title = "Telnet Service Open",
            Description = "Telnet transmits data (including passwords) in plain text. " +
                          "This is one of the most dangerous services to leave open.",
            Severity = SecuritySeverity.Critical,
            Recommendation = "Disable Telnet immediately. If remote access is needed, use SSH (port 22) instead. " +
                             "Check your device's admin panel to disable Telnet access.",
            AffectedService = "Telnet",
            AffectedPort = 23
        });
    }

    private static void CheckFtpExposure(NetworkDevice device)
    {
        if (!HasPort(device, 21)) return;

        device.Findings.Add(new SecurityFinding
        {
            Title = "FTP Service Open",
            Description = "FTP transfers files and credentials without encryption. " +
                          "Anyone on the network could intercept transferred files and passwords.",
            Severity = SecuritySeverity.High,
            Recommendation = "Disable FTP and use SFTP (over SSH) or a secure file sharing method instead. " +
                             "If FTP must be used, ensure it is restricted to trusted users only.",
            AffectedService = "FTP",
            AffectedPort = 21
        });
    }

    private static void CheckSmbExposure(NetworkDevice device)
    {
        if (!HasPort(device, 445) && !HasPort(device, 139)) return;

        var severity = device.Category is DeviceCategory.NAS or DeviceCategory.Server
            ? SecuritySeverity.Medium
            : SecuritySeverity.High;

        string extra = device.Category is DeviceCategory.NAS or DeviceCategory.Server
            ? "Since this is a file server/NAS, SMB is expected — but make sure it's password-protected."
            : "This device doesn't appear to be a file server, so open file sharing is suspicious.";

        device.Findings.Add(new SecurityFinding
        {
            Title = "File Sharing (SMB) Open",
            Description = $"Windows File Sharing (SMB) is accessible. {extra} " +
                          "SMB has been exploited in major attacks like WannaCry.",
            Severity = severity,
            Recommendation = "Ensure all shared folders require strong passwords. " +
                             "Disable SMBv1 if enabled (older, vulnerable protocol). " +
                             "On Windows, go to 'Turn Windows features on or off' and disable 'SMB 1.0/CIFS'.",
            AffectedService = "SMB",
            AffectedPort = 445
        });
    }

    private static void CheckRdpExposure(NetworkDevice device)
    {
        if (!HasPort(device, 3389)) return;

        device.Findings.Add(new SecurityFinding
        {
            Title = "Remote Desktop (RDP) Open",
            Description = "Remote Desktop is accessible on the network. RDP is a frequent " +
                          "target for brute-force attacks and has had critical vulnerabilities.",
            Severity = SecuritySeverity.High,
            Recommendation = "Disable Remote Desktop if not needed (Settings > System > Remote Desktop). " +
                             "If needed, enable Network Level Authentication (NLA), use a strong " +
                             "password, and consider limiting access to specific IP addresses.",
            AffectedService = "RDP",
            AffectedPort = 3389
        });
    }

    private static void CheckVncExposure(NetworkDevice device)
    {
        if (!HasPort(device, 5900)) return;

        device.Findings.Add(new SecurityFinding
        {
            Title = "VNC Remote Access Open",
            Description = "VNC remote desktop access is open. VNC often has weak " +
                          "authentication and transmits screen data without encryption.",
            Severity = SecuritySeverity.High,
            Recommendation = "Disable VNC if not needed. If required, set a strong password, " +
                             "use an encrypted VNC variant, and restrict access to trusted devices only.",
            AffectedService = "VNC",
            AffectedPort = 5900
        });
    }

    private static void CheckHttpAdminPanels(NetworkDevice device)
    {
        bool hasHttp = HasPort(device, 80) || HasPort(device, 8080) || HasPort(device, 8888);
        if (!hasHttp) return;

        if (device.Category is DeviceCategory.Router or DeviceCategory.IoTDevice
            or DeviceCategory.SecurityCamera or DeviceCategory.NAS)
        {
            device.Findings.Add(new SecurityFinding
            {
                Title = "Web Admin Panel Detected",
                Description = $"This {device.CategoryName} has a web admin panel accessible over HTTP (unencrypted). " +
                              "Default admin credentials are a common attack vector.",
                Severity = SecuritySeverity.Medium,
                Recommendation = "1) Change the default admin password to a strong, unique password.\n" +
                                 "2) If possible, enable HTTPS for the admin panel.\n" +
                                 "3) Check for firmware updates from the manufacturer.\n" +
                                 "4) Disable remote management if not needed.",
                AffectedService = "HTTP Admin",
                AffectedPort = 80
            });
        }
    }

    private static void CheckUnencryptedMail(NetworkDevice device)
    {
        bool hasPop3 = HasPort(device, 110);
        bool hasImap = HasPort(device, 143);
        bool hasSmtp = HasPort(device, 25);

        if (!hasPop3 && !hasImap && !hasSmtp) return;

        var services = new List<string>();
        if (hasSmtp) services.Add("SMTP (25)");
        if (hasPop3) services.Add("POP3 (110)");
        if (hasImap) services.Add("IMAP (143)");

        device.Findings.Add(new SecurityFinding
        {
            Title = "Unencrypted Email Services",
            Description = $"Unencrypted mail services detected: {string.Join(", ", services)}. " +
                          "Emails and credentials sent over these ports can be intercepted.",
            Severity = SecuritySeverity.Medium,
            Recommendation = "Use encrypted email protocols instead: SMTPS (587), IMAPS (993), POP3S (995). " +
                             "Configure your email client to use SSL/TLS connections.",
            AffectedService = string.Join(", ", services)
        });
    }

    private static void CheckUpnpExposure(NetworkDevice device)
    {
        if (!HasPort(device, 1900) && !HasPort(device, 5000) && !HasPort(device, 49152)) return;

        device.Findings.Add(new SecurityFinding
        {
            Title = "UPnP Service Active",
            Description = "Universal Plug and Play (UPnP) is active. UPnP can allow devices to " +
                          "automatically open ports on your router, potentially exposing services to the internet.",
            Severity = SecuritySeverity.Medium,
            Recommendation = "Disable UPnP on your router unless you specifically need it. " +
                             "Go to your router's admin panel and look for UPnP settings under " +
                             "the 'Advanced' or 'NAT' section.",
            AffectedService = "UPnP",
            AffectedPort = 1900
        });
    }

    private static void CheckMqttExposure(NetworkDevice device)
    {
        if (!HasPort(device, 1883)) return;

        device.Findings.Add(new SecurityFinding
        {
            Title = "MQTT Broker Open (IoT)",
            Description = "An MQTT message broker is running without encryption. MQTT is used by many " +
                          "smart home devices. An open broker could allow anyone to monitor or control IoT devices.",
            Severity = SecuritySeverity.High,
            Recommendation = "Enable authentication on the MQTT broker and switch to MQTTS (port 8883) " +
                             "for encrypted communication. Update the broker's configuration to require " +
                             "username/password authentication.",
            AffectedService = "MQTT",
            AffectedPort = 1883
        });
    }

    private static void CheckDatabaseExposure(NetworkDevice device)
    {
        bool hasMssql = HasPort(device, 1433);
        bool hasMysql = HasPort(device, 3306);

        if (!hasMssql && !hasMysql) return;

        string dbName = hasMssql ? "Microsoft SQL Server" : "MySQL";
        int port = hasMssql ? 1433 : 3306;

        device.Findings.Add(new SecurityFinding
        {
            Title = $"Database Server Exposed ({dbName})",
            Description = $"A {dbName} database is accepting connections on the network. " +
                          "Databases should generally not be directly accessible on the network.",
            Severity = SecuritySeverity.High,
            Recommendation = $"Restrict {dbName} to only accept connections from localhost or " +
                             "specific trusted IP addresses. Use the database's firewall/bind-address " +
                             "settings to limit access. Ensure a strong password is set.",
            AffectedService = dbName,
            AffectedPort = port
        });
    }

    private static void CheckDefaultCameraStreams(NetworkDevice device)
    {
        if (device.Category != DeviceCategory.SecurityCamera) return;
        if (!HasPort(device, 554)) return;

        device.Findings.Add(new SecurityFinding
        {
            Title = "Camera RTSP Stream Accessible",
            Description = "This security camera's RTSP video stream is accessible on the network. " +
                          "If using default credentials, anyone could view the camera feed.",
            Severity = SecuritySeverity.High,
            Recommendation = "1) Change the camera's default password immediately.\n" +
                             "2) Update the camera firmware to the latest version.\n" +
                             "3) Consider placing cameras on a separate VLAN/network.\n" +
                             "4) Disable RTSP if you only use the manufacturer's app.",
            AffectedService = "RTSP",
            AffectedPort = 554
        });
    }

    private static void CheckIoTDeviceSecurity(NetworkDevice device)
    {
        if (device.Category is not (DeviceCategory.IoTDevice or DeviceCategory.SmartSpeaker))
            return;

        if (device.OpenPorts.Count > 3)
        {
            device.Findings.Add(new SecurityFinding
            {
                Title = "IoT Device Has Many Open Ports",
                Description = $"This {device.CategoryName} has {device.OpenPorts.Count} open ports, " +
                              "which is more than expected for a smart home device. Each open port is " +
                              "a potential attack surface.",
                Severity = SecuritySeverity.Medium,
                Recommendation = "Check for firmware updates for this device. Consider placing " +
                                 "smart home devices on a separate Wi-Fi network (guest network) " +
                                 "to isolate them from your main devices.",
                AffectedService = "Multiple"
            });
        }
    }

    private static void CheckRouterSecurity(NetworkDevice device)
    {
        if (device.Category != DeviceCategory.Router) return;

        if (HasPort(device, 23))
        {
            device.Findings.Add(new SecurityFinding
            {
                Title = "Router Has Telnet Enabled",
                Description = "Your router has Telnet enabled, which is a critical security risk. " +
                              "Attackers could gain full control of your network through this service.",
                Severity = SecuritySeverity.Critical,
                Recommendation = "Log into your router's admin panel and disable Telnet access immediately. " +
                                 "Use the web admin interface or SSH for management instead. " +
                                 "Also check that your router firmware is up to date.",
                AffectedService = "Telnet",
                AffectedPort = 23
            });
        }

        if (HasPort(device, 80) && !HasPort(device, 443))
        {
            device.Findings.Add(new SecurityFinding
            {
                Title = "Router Admin Over HTTP Only",
                Description = "Your router's admin panel is only available over unencrypted HTTP. " +
                              "Your admin password could be intercepted when you log in.",
                Severity = SecuritySeverity.Medium,
                Recommendation = "Check if your router supports HTTPS for the admin panel and enable it. " +
                                 "Consider upgrading your router if it doesn't support encrypted management.",
                AffectedService = "HTTP",
                AffectedPort = 80
            });
        }
    }

    private static bool HasPort(NetworkDevice device, int port) =>
        device.OpenPorts.Any(p => p.Port == port);
}
