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
    [ObservableProperty] private string _subnetInfo = "Not scanned yet";
    [ObservableProperty] private bool _isScanning;
    [ObservableProperty] private double _scanProgress;
    [ObservableProperty] private string _scanProgressText = "";
    [ObservableProperty] private DeviceViewModel? _selectedDevice;

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
        _networkScanner.StatusUpdate += msg => Application.Current.Dispatcher.Invoke(() => StatusText = msg);
        _portScanner.StatusUpdate += msg => Application.Current.Dispatcher.Invoke(() => StatusText = msg);
    }

    [RelayCommand(CanExecute = nameof(CanStartScan))]
    private async Task StartScanAsync()
    {
        IsScanning = true;
        _cts = new CancellationTokenSource();
        Devices.Clear();
        SelectedDevice = null;
        ScanProgress = 0;

        try
        {
            // Phase 1: Detect subnet
            ScanProgressText = "Detecting network...";
            StatusText = "Detecting local network configuration...";
            var (gateway, cidr, localIp) = _subnetDetector.Detect();
            SubnetInfo = $"{cidr}  |  Gateway: {gateway}  |  Your IP: {localIp}";
            ScanProgress = 5;

            // Phase 2: Discover devices
            ScanProgressText = "Discovering devices...";
            var hosts = _subnetDetector.GetSubnetHosts(cidr).ToList();
            var devices = await _networkScanner.DiscoverDevicesAsync(hosts, _cts.Token);

            // Mark the gateway
            var gatewayDevice = devices.FirstOrDefault(d => d.IpAddress.Equals(gateway));
            if (gatewayDevice is not null)
                gatewayDevice.IsGateway = true;

            ScanProgress = 40;

            // Phase 3: Port scan each device
            ScanProgressText = "Scanning ports...";
            int scanned = 0;
            foreach (var device in devices)
            {
                _cts.Token.ThrowIfCancellationRequested();
                await _portScanner.ScanDeviceAsync(device, _cts.Token);
                scanned++;
                ScanProgress = 40 + (40.0 * scanned / devices.Count);
            }

            // Phase 4: Classify devices
            ScanProgressText = "Classifying devices...";
            _classifier.ClassifyAll(devices);
            ScanProgress = 85;

            // Phase 5: Security analysis
            ScanProgressText = "Analyzing security...";
            _analyzer.AnalyzeAll(devices);
            ScanProgress = 95;

            // Populate the UI collection
            foreach (var device in devices.OrderByDescending(d => d.IsGateway)
                                          .ThenByDescending(d => d.Findings.Count)
                                          .ThenBy(d => d.IpAddress.ToString()))
            {
                var vm = new DeviceViewModel(device);
                Devices.Add(vm);
            }

            UpdateSummary(devices);

            ScanProgress = 100;
            ScanProgressText = "Scan complete";
            StatusText = $"Scan complete — {devices.Count} devices found, {devices.Sum(d => d.Findings.Count)} security findings.";
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
