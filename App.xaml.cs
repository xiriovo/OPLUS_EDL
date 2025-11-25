using System.Configuration;
using System.Data;
using System.Windows;

namespace OPLUS_EDL;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
    public partial class App : System.Windows.Application
    {
        public App()
        {
            this.DispatcherUnhandledException += App_DispatcherUnhandledException;
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
        }

        private void App_DispatcherUnhandledException(object sender, System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
        {
            System.Windows.MessageBox.Show($"未捕获的异常 (Dispatcher): {e.Exception.Message}\n\n{e.Exception.StackTrace}", "崩溃", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            e.Handled = true;
        }

        private void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            if (e.ExceptionObject is Exception ex)
            {
                System.Windows.MessageBox.Show($"未捕获的异常 (Domain): {ex.Message}\n\n{ex.StackTrace}", "严重崩溃", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            }
        }
    }

