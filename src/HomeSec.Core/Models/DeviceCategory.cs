namespace HomeSec.Core.Models;

/// <summary>
/// High-level categories for classifying discovered network devices.
/// </summary>
public enum DeviceCategory
{
    Unknown,
    Computer,
    Phone,
    Tablet,
    Router,
    Printer,
    SmartTV,
    GameConsole,
    IoTDevice,
    SmartSpeaker,
    SecurityCamera,
    NAS,
    Server
}

public static class DeviceCategoryExtensions
{
    public static string ToFriendlyName(this DeviceCategory category) => category switch
    {
        DeviceCategory.Unknown => "Unknown Device",
        DeviceCategory.Computer => "Computer / Laptop",
        DeviceCategory.Phone => "Smartphone",
        DeviceCategory.Tablet => "Tablet",
        DeviceCategory.Router => "Router / Gateway",
        DeviceCategory.Printer => "Printer",
        DeviceCategory.SmartTV => "Smart TV",
        DeviceCategory.GameConsole => "Game Console",
        DeviceCategory.IoTDevice => "IoT / Smart Home Device",
        DeviceCategory.SmartSpeaker => "Smart Speaker",
        DeviceCategory.SecurityCamera => "Security Camera",
        DeviceCategory.NAS => "Network Storage (NAS)",
        DeviceCategory.Server => "Server",
        _ => "Unknown Device"
    };

    public static string ToIconGlyph(this DeviceCategory category) => category switch
    {
        DeviceCategory.Computer => "\uE7F8",      // Monitor icon
        DeviceCategory.Phone => "\uE8EA",          // Phone icon
        DeviceCategory.Tablet => "\uE70A",         // Tablet icon
        DeviceCategory.Router => "\uE968",          // Router icon
        DeviceCategory.Printer => "\uE749",         // Printer icon
        DeviceCategory.SmartTV => "\uE7F4",         // TV icon
        DeviceCategory.GameConsole => "\uE7FC",     // Game icon
        DeviceCategory.IoTDevice => "\uEA80",       // IoT icon
        DeviceCategory.SmartSpeaker => "\uE7F5",    // Speaker icon
        DeviceCategory.SecurityCamera => "\uE714",  // Camera icon
        DeviceCategory.NAS => "\uEDA2",             // Storage icon
        DeviceCategory.Server => "\uE977",          // Server icon
        _ => "\uE783"                               // Question mark icon
    };
}
