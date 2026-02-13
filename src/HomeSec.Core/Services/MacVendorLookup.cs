namespace HomeSec.Core.Services;

/// <summary>
/// Looks up device manufacturer from MAC address OUI (first 3 octets).
/// Contains a curated list of common home-network device vendors.
/// </summary>
public static class MacVendorLookup
{
    private static readonly Dictionary<string, string> OuiDatabase = new(StringComparer.OrdinalIgnoreCase)
    {
        // Apple
        { "00:1C:B3", "Apple" }, { "3C:15:C2", "Apple" }, { "AC:DE:48", "Apple" },
        { "F0:18:98", "Apple" }, { "14:7D:DA", "Apple" }, { "A4:83:E7", "Apple" },
        { "00:03:93", "Apple" }, { "D0:25:98", "Apple" }, { "28:6A:BA", "Apple" },

        // Samsung
        { "00:1A:8A", "Samsung" }, { "54:92:BE", "Samsung" }, { "AC:5F:3E", "Samsung" },
        { "BC:72:B1", "Samsung" }, { "E4:7C:F9", "Samsung" }, { "00:26:37", "Samsung" },

        // Google / Nest
        { "F4:F5:D8", "Google" }, { "54:60:09", "Google" }, { "A4:77:33", "Google" },
        { "18:D6:C7", "Google Nest" }, { "64:16:66", "Google Nest" },

        // Amazon
        { "FC:65:DE", "Amazon" }, { "74:C2:46", "Amazon" }, { "A0:02:DC", "Amazon" },
        { "00:FC:8B", "Amazon" }, { "44:65:0D", "Amazon Echo" },

        // Microsoft / Xbox
        { "00:50:F2", "Microsoft" }, { "7C:1E:52", "Microsoft" },
        { "60:45:BD", "Microsoft Xbox" }, { "7C:ED:8D", "Microsoft Xbox" },

        // Sony / PlayStation
        { "00:1D:0D", "Sony" }, { "AC:B3:13", "Sony" },
        { "00:04:1F", "Sony PlayStation" }, { "F8:D0:AC", "Sony PlayStation" },

        // Nintendo
        { "00:1F:32", "Nintendo" }, { "00:1B:EA", "Nintendo" }, { "34:AF:2C", "Nintendo" },
        { "58:2F:40", "Nintendo" }, { "78:A2:A0", "Nintendo" },

        // Network equipment
        { "00:18:0A", "Cisco" }, { "00:1B:2A", "Cisco" }, { "B0:7D:47", "Cisco" },
        { "E0:46:9A", "Netgear" }, { "A4:2B:8C", "Netgear" }, { "C0:3F:0E", "Netgear" },
        { "00:14:BF", "Linksys" }, { "00:1A:70", "Linksys" }, { "C0:56:27", "Belkin" },
        { "EC:08:6B", "TP-Link" }, { "50:C7:BF", "TP-Link" }, { "C0:25:E9", "TP-Link" },
        { "00:24:B2", "ASUS" }, { "1C:87:2C", "ASUS" }, { "04:D4:C4", "ASUS" },
        { "08:10:79", "D-Link" }, { "34:08:04", "D-Link" },
        { "00:1D:7E", "Ubiquiti" }, { "24:5A:4C", "Ubiquiti" }, { "F4:92:BF", "Ubiquiti" },

        // Smart home / IoT
        { "D0:73:D5", "Philips Hue" }, { "00:17:88", "Philips Hue" },
        { "B0:CE:18", "Ring" }, { "34:3D:C4", "Ring" },
        { "18:B4:30", "Nest" }, { "64:16:7F", "Nest" },
        { "68:37:E9", "Sonos" }, { "54:2A:1B", "Sonos" },
        { "00:1E:C0", "Roku" }, { "AC:3A:7A", "Roku" },
        { "50:14:79", "LG Electronics" }, { "00:1C:62", "LG Electronics" },
        { "8C:79:F5", "Samsung SmartThings" },
        { "00:04:20", "Wyze" },
        { "B4:E6:2D", "Raspberry Pi" }, { "DC:A6:32", "Raspberry Pi" },

        // Printers
        { "00:1B:A9", "Brother" }, { "00:80:77", "Brother" },
        { "00:1E:0B", "HP" }, { "3C:D9:2B", "HP" }, { "94:57:A5", "HP" },
        { "00:00:74", "Epson" }, { "00:26:AB", "Epson" },
        { "00:00:85", "Canon" }, { "18:0C:AC", "Canon" },

        // Intel (often laptops/desktops)
        { "00:1B:21", "Intel" }, { "68:05:CA", "Intel" }, { "8C:8D:28", "Intel" },

        // Realtek (common in PCs)
        { "00:E0:4C", "Realtek" }, { "52:54:00", "Realtek (VM)" },

        // Dell
        { "00:14:22", "Dell" }, { "18:03:73", "Dell" }, { "F8:BC:12", "Dell" },

        // Lenovo
        { "00:06:1B", "Lenovo" }, { "28:D2:44", "Lenovo" }, { "E8:2A:44", "Lenovo" },
    };

    /// <summary>
    /// Returns the vendor name for the given MAC address, or null if unknown.
    /// </summary>
    public static string? GetVendor(string? macAddress)
    {
        if (string.IsNullOrWhiteSpace(macAddress))
            return null;

        // Normalize: take first 3 octets, replace dashes with colons
        string normalized = macAddress.Replace('-', ':').ToUpperInvariant();
        if (normalized.Length < 8) return null;

        string oui = normalized[..8]; // "AA:BB:CC"

        return OuiDatabase.TryGetValue(oui, out var vendor) ? vendor : null;
    }
}
