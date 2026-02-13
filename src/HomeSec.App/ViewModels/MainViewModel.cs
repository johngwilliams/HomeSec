using System.Collections.ObjectModel;
using System.Net;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HomeSec.Core.Models;
using HomeSec.Core.Services;

namespace HomeSec.App.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly SubnetDetector _subnetDetector = new();
    private readonly NetworkScanner _networkScanner = new();
    private readonly PortScanner _portScanner = new();
    private readonly DeviceClassifier _classifier = new();
    private readonly SecurityAnalyzer _analyzer = new();

    private CancellationTokenSource? _cts;

    [ObservableProperty] private string _statusText = "Ready — click 'Scan Network' to begin.";
    [ObservableProperty] private string _subnetDetail = "";
    [ObservableProperty] private bool _isScanning;
    [ObservableProperty] private double _scanProgress;
    [ObservableProperty] private string _scanProgressText = "";
    [ObservableProperty] private DeviceViewModel? _selectedDevice;

    // Subnet selection
    public ObservableCollection<SubnetInfo> AvailableSubnets { get; } = [];
    [ObservableProperty] private SubnetInfo? _selectedSubnet;
    [ObservableProperty] private bool _hasSubnets;

    // Summary stats
    [ObservableProperty] private int _totalDevices;
    [ObservableProperty] private int _totalFindings;
    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _highCount;
    [ObservableProperty] private int _mediumCount;
    [ObservableProperty] private int _lowCount;
    [ObservableProperty] private string _overallRisk = "Unknown";

    public ObservableCollection<DeviceViewModel> Devices { get; } = [];

    public MainViewModel()
    {
        _networkScanner.StatusUpdate += OnStatus;
        _portScanner.StatusUpdate += OnStatus;

        RefreshSubnets();
    }

    partial void OnSelectedSubnetChanged(SubnetInfo? value)
    {
        SubnetDetail = value?.DetailLabel ?? "";
    }

    [RelayCommand]
    private void RefreshSubnets()
    {
        try
        {
            var subnets = _subnetDetector.DetectAll();
            AvailableSubnets.Clear();
            foreach (var s in subnets)
                AvailableSubnets.Add(s);

            HasSubnets = AvailableSubnets.Count > 0;

            // Default to the first Class C subnet, otherwise the first available
            SelectedSubnet = AvailableSubnets.FirstOrDefault(s => s.IsClassC)
                             ?? AvailableSubnets.FirstOrDefault();

            if (!HasSubnets)
                StatusText = "No network interfaces found. Check your connection.";
            else
                StatusText = $"Found {AvailableSubnets.Count} subnet(s). Select one and click 'Scan Network'.";
        }
        catch (Exception ex)
        {
            StatusText = $"Error detecting subnets: {ex.Message}";
        }
    }

    private void OnStatus(string msg)
    {
        Application.Current.Dispatcher.BeginInvoke(() => StatusText = msg);
    }

    private void SetProgress(double value, string? text = null)
    {
        Application.Current.Dispatcher.BeginInvoke(() =>
        {
            ScanProgress = value;
            if (text is not null) ScanProgressText = text;
        });
    }

    [RelayCommand(CanExecute = nameof(CanStartScan))]
    private async Task StartScanAsync()
    {
        if (SelectedSubnet is null)
        {
            StatusText = "Please select a subnet to scan.";
            return;
        }

        IsScanning = true;
        _cts = new CancellationTokenSource();
        Devices.Clear();
        SelectedDevice = null;
        ScanProgress = 0;

        var token = _cts.Token;
        var subnet = SelectedSubnet;

        try
        {
            var devices = await Task.Run(async () =>
            {
                // Phase 1: Enumerate hosts in the selected subnet
                SetProgress(2, "Detecting network...");
                var hosts = _subnetDetector.GetSubnetHosts(subnet.Cidr).ToList();
                SetProgress(5, $"Discovering devices on {subnet.Cidr}...");

                // Phase 2: Discover devices (ping sweep)
                var found = await _networkScanner.DiscoverDevicesAsync(hosts, token);

                var gatewayDevice = found.FirstOrDefault(d => d.IpAddress.Equals(subnet.Gateway));
                if (gatewayDevice is not null)
                    gatewayDevice.IsGateway = true;

                SetProgress(40, $"Found {found.Count} devices. Scanning ports...");

                // Phase 3: Port scan all devices in parallel
                await _portScanner.ScanAllDevicesAsync(found, done =>
                {
                    double pct = 40 + (40.0 * done / found.Count);
                    SetProgress(pct, $"Port scanning... ({done}/{found.Count})");
                }, token);

                SetProgress(85, "Classifying devices...");

                // Phase 4: Classify
                _classifier.ClassifyAll(found);
                SetProgress(90, "Analyzing security...");

                // Phase 5: Security analysis
                _analyzer.AnalyzeAll(found);
                SetProgress(95);

                return found;
            }, token);

            // Back on UI thread — populate the list
            foreach (var device in devices.OrderByDescending(d => d.IsGateway)
                                          .ThenByDescending(d => d.Findings.Count)
                                          .ThenBy(d => d.IpAddress.ToString()))
            {
                Devices.Add(new DeviceViewModel(device));
            }

            UpdateSummary(devices);
            ScanProgress = 100;
            ScanProgressText = "Scan complete";
            StatusText = $"Scan complete — {devices.Count} devices found, " +
                         $"{devices.Sum(d => d.Findings.Count)} security findings.";
        }
        catch (OperationCanceledException)
        {
            StatusText = "Scan cancelled.";
            ScanProgressText = "Cancelled";
        }
        catch (Exception ex)
        {
            StatusText = $"Error: {ex.Message}";
            ScanProgressText = "Error";
            MessageBox.Show(
                $"An error occurred during the scan:\n\n{ex.Message}\n\n" +
                "Make sure you're connected to a network and try running the app as Administrator.",
                "Scan Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            IsScanning = false;
            _cts?.Dispose();
            _cts = null;
        }
    }

    private bool CanStartScan() => !IsScanning;

    [RelayCommand]
    private void StopScan()
    {
        _cts?.Cancel();
    }

    private void UpdateSummary(List<NetworkDevice> devices)
    {
        TotalDevices = devices.Count;
        TotalFindings = devices.Sum(d => d.Findings.Count);
        CriticalCount = devices.Sum(d => d.Findings.Count(f => f.Severity == SecuritySeverity.Critical));
        HighCount = devices.Sum(d => d.Findings.Count(f => f.Severity == SecuritySeverity.High));
        MediumCount = devices.Sum(d => d.Findings.Count(f => f.Severity == SecuritySeverity.Medium));
        LowCount = devices.Sum(d => d.Findings.Count(f => f.Severity == SecuritySeverity.Low));

        if (CriticalCount > 0) OverallRisk = "Critical";
        else if (HighCount > 0) OverallRisk = "High";
        else if (MediumCount > 0) OverallRisk = "Medium";
        else if (LowCount > 0) OverallRisk = "Low";
        else OverallRisk = "Good";
    }
}
