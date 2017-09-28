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
            UpdateServiceStatus(ServiceState.SERVICE_START_PENDING);

            evntLog.WriteEntry($"{ServiceName} is starting...", EventLogEntryType.Information);
            
            UpdateServiceStatus(ServiceState.SERVICE_RUNNING);

            evntLog.WriteEntry($"{ServiceName} has started.", EventLogEntryType.Information);
        }

        protected override void OnStop()
        {
            UpdateServiceStatus(ServiceState.SERVICE_STOP_PENDING);

            evntLog.WriteEntry($"{ServiceName} is stopping...", EventLogEntryType.Information);

            UpdateServiceStatus(ServiceState.SERVICE_STOPPED);
            
            evntLog.WriteEntry($"{ServiceName} has stopped.", EventLogEntryType.Information);
        }

        private void AddressChangedCallback(object sender, EventArgs e)
        {
            if (!NetworkInterface.GetIsNetworkAvailable()) return;

            var networkInterface = NetworkInterface.GetAllNetworkInterfaces().First(i => i.NetworkInterfaceType == NetworkInterfaceType.Ethernet && i.Name.Equals("PIA"));

            if (networkInterface != null)
                evntLog.WriteEntry(networkInterface.OperationalStatus == OperationalStatus.Up ? "PIA is connected." : "PIA is disconnected.");
            else
                evntLog.WriteEntry("PIA Adapter could not be found.");
        }

        private void UpdateServiceStatus(ServiceState serviceState)
        {
            try
            {
                var passedStateName = Enum.GetName(typeof(ServiceState), serviceState);

                var isPendingState = passedStateName != null && passedStateName.Contains("PENDING");

                var serviceStatus = new ServiceStatus
                {
                    dwCurrentState = serviceState,
                    dwWaitHint = isPendingState ? 100000 : 0
                };
                
                SetServiceStatus(ServiceHandle, ref serviceStatus);
            }
            catch (Exception ex)
            {
                evntLog.WriteEntry($"Something went wrong: {ex.Message}");
            }
        }
    }
}
