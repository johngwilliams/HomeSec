using CommunityToolkit.Mvvm.ComponentModel;
using HomeSec.Core.Models;

namespace HomeSec.App.ViewModels;

public partial class DeviceViewModel : ObservableObject
{
    [ObservableProperty] private string _ipAddress = "";
    [ObservableProperty] private string _displayName = "";
    [ObservableProperty] private string _macAddress = "";
    [ObservableProperty] private string _vendor = "";
    [ObservableProperty] private string _categoryName = "";
    [ObservableProperty] private string _categoryIcon = "";
    [ObservableProperty] private string _operatingSystem = "";
    [ObservableProperty] private bool _isGateway;
    [ObservableProperty] private int _openPortCount;
    [ObservableProperty] private int _findingCount;
    [ObservableProperty] private string _highestSeverity = "";
    [ObservableProperty] private bool _isSelected;

    public NetworkDevice Model { get; }
    public List<PortInfo> OpenPorts => Model.OpenPorts;
    public List<SecurityFinding> Findings => Model.Findings;

    public DeviceViewModel(NetworkDevice device)
    {
        Model = device;
        Refresh();
    }

    public void Refresh()
    {
        IpAddress = Model.IpAddress.ToString();
        DisplayName = Model.DisplayName;
        MacAddress = Model.MacAddress ?? "Unknown";
        Vendor = Model.Vendor ?? "Unknown";
        CategoryName = Model.CategoryName;
        CategoryIcon = Model.Category.ToIconGlyph();
        OperatingSystem = Model.OperatingSystem ?? "Unknown";
        IsGateway = Model.IsGateway;
        OpenPortCount = Model.OpenPorts.Count;
        FindingCount = Model.Findings.Count;

        HighestSeverity = Model.Findings.Count > 0
            ? Model.Findings.Max(f => f.Severity).ToString()
            : "None";
    }
}
