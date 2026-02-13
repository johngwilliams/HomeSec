using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace HomeSec.App.Converters;

public class SeverityToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        string severity = value?.ToString() ?? "";
        return severity switch
        {
            "Critical" => new SolidColorBrush(Color.FromRgb(220, 38, 38)),   // Red
            "High" => new SolidColorBrush(Color.FromRgb(234, 88, 12)),       // Orange
            "Medium" => new SolidColorBrush(Color.FromRgb(202, 138, 4)),     // Yellow/Amber
            "Low" => new SolidColorBrush(Color.FromRgb(22, 163, 74)),        // Green
            "Good" => new SolidColorBrush(Color.FromRgb(22, 163, 74)),       // Green
            "None" => new SolidColorBrush(Color.FromRgb(107, 114, 128)),     // Gray
            _ => new SolidColorBrush(Color.FromRgb(107, 114, 128))
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

public class SeverityToBackgroundConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        string severity = value?.ToString() ?? "";
        return severity switch
        {
            "Critical" => new SolidColorBrush(Color.FromArgb(30, 220, 38, 38)),
            "High" => new SolidColorBrush(Color.FromArgb(25, 234, 88, 12)),
            "Medium" => new SolidColorBrush(Color.FromArgb(20, 202, 138, 4)),
            "Low" => new SolidColorBrush(Color.FromArgb(15, 22, 163, 74)),
            _ => new SolidColorBrush(Colors.Transparent)
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

public class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is true ? System.Windows.Visibility.Visible : System.Windows.Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

public class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is true ? System.Windows.Visibility.Collapsed : System.Windows.Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}
