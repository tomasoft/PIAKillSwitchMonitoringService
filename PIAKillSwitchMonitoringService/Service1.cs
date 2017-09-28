using System;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.ServiceProcess;
using System.Runtime.InteropServices;

namespace PIAKillSwitchMonitoringService
{
    public partial class PiaKillSwitchMonitoringService : ServiceBase
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetServiceStatus(IntPtr handle, ref ServiceStatus serviceStatus);

        public PiaKillSwitchMonitoringService()
        {
            InitializeComponent();

            NetworkChange.NetworkAddressChanged += AddressChangedCallback;
        }

        protected override void OnStart(string[] args)
        {
            evntLog.WriteEntry($"{ServiceName} is starting...", EventLogEntryType.Information);

            // Update the service state to Start Pending.  
            var serviceStatus = new ServiceStatus
            {
                dwCurrentState = ServiceState.SERVICE_START_PENDING,
                dwWaitHint = 100000
            };

            SetServiceStatus(ServiceHandle, ref serviceStatus);

            // Update the service state to Running.  
            serviceStatus.dwCurrentState = ServiceState.SERVICE_RUNNING;

            SetServiceStatus(ServiceHandle, ref serviceStatus);

            evntLog.WriteEntry($"{ServiceName} has started.", EventLogEntryType.Information);
        }

        protected override void OnStop()
        {
            evntLog.WriteEntry($"{ServiceName} is stopping...", EventLogEntryType.Information);

            // Update the service state to Start Pending.  
            var serviceStatus = new ServiceStatus
            {
                dwCurrentState = ServiceState.SERVICE_STOP_PENDING,
                dwWaitHint = 100000
            };

            SetServiceStatus(ServiceHandle, ref serviceStatus);

            // Update the service state to Running.  
            serviceStatus.dwCurrentState = ServiceState.SERVICE_STOPPED;

            SetServiceStatus(ServiceHandle, ref serviceStatus);

            evntLog.WriteEntry($"{ServiceName} has stopped.", EventLogEntryType.Information);
        }

        private void AddressChangedCallback(object sender, EventArgs e)
        {
            var adapters = NetworkInterface.GetAllNetworkInterfaces();

            foreach (var n in adapters.Where(a => a.Name.Equals("PIA")))
            {
                evntLog.WriteEntry($"{n.Name} is {n.OperationalStatus}");
            }
        }
    }
}
