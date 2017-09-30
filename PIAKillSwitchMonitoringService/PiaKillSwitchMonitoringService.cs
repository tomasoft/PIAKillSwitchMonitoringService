#region Usings
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.ServiceProcess;
using System.Runtime.InteropServices;
//using System.Security.Principal;
using FirewallTesting; 
#endregion

#region Things to consider/reference...
/*
 netsh args : https://technet.microsoft.com/en-us/library/dd734783(v=ws.10).aspx 
 Change outbound connections behaviour in windows advanced firewall to blocked for all used profiles.
 Set PIA client to use tcp and port 443
 The ports we need for connection are 110, 443, 9201.
 To kill everything we only allow these ports and disable everything else.
*/
#endregion

namespace PIAKillSwitchMonitoringService
{
    public partial class PiaKillSwitchMonitoringService : ServiceBase
    {
        /// Pinvoke
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetServiceStatus(IntPtr handle, ref ServiceStatus serviceStatus);

        // Holds a list with all rules we need
        private static readonly List<FirewallRule> FirewallRules = new List<FirewallRule>();

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

            CreateKillSwitchRules();

            CleanUpFirewallRules();

            EnableKillSwitch(FirewallRules, true);
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
                if (networkInterface.OperationalStatus == OperationalStatus.Up)
                {
                    evntLog.WriteEntry("PIA is connected. Disabling kill switch...");
                    EnableKillSwitch(FirewallRules, false);
                }
                else
                {
                    evntLog.WriteEntry("PIA is disconnected. Enabling kill switch...");
                    EnableKillSwitch(FirewallRules, true);
                }
            
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

        #region AddFirewallRule
        /// <summary>
        /// Creates a firewall rule.
        /// </summary>
        private static void AddFirewallRule(IEnumerable<FirewallRule> firewallRule)
        {
            FirewallRules.AddRange(firewallRule);
        }
        #endregion

        #region CreateKillSwitchRules
        /// <summary>
        /// Adds the required firewall rules for further proccessing.
        /// </summary>
        private static void CreateKillSwitchRules()
        {
            AddFirewallRule(new List<FirewallRule>()
            {
                new FirewallRule() { Action = FirewallRuleParams.Action.Allow, Dir = FirewallRuleParams.Direction.Out, InterfaceType = FirewallRuleParams.InterfaceType.Any, Program = "all", Localport = "any", Remoteport = "110,443,9201", Protocol = FirewallRuleParams.ProtocolType.Tcp, Profile = FirewallRuleParams.Profile.Any, Name = "#PIA Client"},
                new FirewallRule() { Action = FirewallRuleParams.Action.Allow, Dir = FirewallRuleParams.Direction.Out, InterfaceType = FirewallRuleParams.InterfaceType.Any, Program = "all", Localport = "all ports", Remoteport = "all ports", Protocol = FirewallRuleParams.ProtocolType.Any, Profile = FirewallRuleParams.Profile.Any, Name = "#Allow Everything"}
            });
        }

        #endregion

        #region CleanUpExistingRules
        /// <summary>
        /// Removes existing rules with same rule name.
        /// </summary>
        private static void CleanUpFirewallRules()
        {
            foreach (var firewallRule in FirewallRules)
            {
                // Remove existing rule
                ExecuteCommand("netsh.exe", $"advfirewall firewall delete rule name=\"{firewallRule.Name}\"", out var _, out var _);
            }
        }
        #endregion

        #region EnableKillSwitch
        /// <summary>
        /// Adds a rule to block port 80 an all wireless adapters
        /// and activates (enables) the rule
        /// </summary>
        /// <param name="firewallRules">Firewall rules needed for the kill switch.</param>
        /// <param name="enabled">Defines if rules will be enabled or not.</param>
        /// <returns></returns>
        private static void EnableKillSwitch(IEnumerable<FirewallRule> firewallRules, bool enabled)
        {
            var enable = enabled ? "yes" : "no";
            var toggled = !enabled ? "yes" : "no";

            foreach (var firewallRule in firewallRules)
            {
                var args = string.Empty;
                var ret = default(int);
                var stdout = string.Empty;
                var stderr = string.Empty;

                if (firewallRule.Protocol != FirewallRuleParams.ProtocolType.Any)
                {
                    // Add rule
                    args = $"advfirewall firewall add rule name=\"{firewallRule.Name}\" " +
                               $"dir={firewallRule.Dir.ToString().ToLower()} " +
                               $"action={firewallRule.Action.ToString().ToLower()} " +
                               $"enable={enable} " +
                               $"protocol={firewallRule.Protocol.ToString().ToLower()} " +
                               $"localport={firewallRule.Localport} " +
                               $"remoteport={firewallRule.Remoteport} " +
                               $"profile={firewallRule.Profile.ToString().ToLower()} " +
                               $"interfacetype={firewallRule.InterfaceType.ToString().ToLower()}";
                    ret = ExecuteCommand("netsh.exe", args, out stdout, out stderr);
                }
                else
                {
                    // Add rule
                    args = $"advfirewall firewall add rule name=\"{firewallRule.Name}\" " +
                               $"dir={firewallRule.Dir.ToString().ToLower()} " +
                               $"action={firewallRule.Action.ToString().ToLower()} " +
                               $"enable={toggled} " +
                               $"protocol={firewallRule.Protocol.ToString().ToLower()} " +
                               $"profile={firewallRule.Profile.ToString().ToLower()} " +
                               $"interfacetype={firewallRule.InterfaceType.ToString().ToLower()}";
                    ret = ExecuteCommand("netsh.exe", args, out stdout, out stderr);
                }

                Console.WriteLine(stdout);
                Console.WriteLine(stderr);
                Console.WriteLine(ret);
            }
        }
        #endregion

        //#region CheckIfUserIsAdmin
        ///// <summary>
        ///// Checks if currently logged in user is an admin.
        ///// </summary>
        ///// <returns></returns>
        //private static bool UserIsAdmin()
        //{
        //    // Are we an admin, cause if we are no canges will be made!
        //    return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        //}
        //#endregion

        #region ExecuteCommand
        /// <summary>
        /// Runs a process with elevated privileges.
        /// </summary>
        /// <param name="command">The command (executable).</param>
        /// <param name="args">Command arguments</param>
        /// <param name="stdout">The stdout redirection.</param>
        /// <param name="stderr">The stderr redirection.</param>
        /// <param name="waitForCompletion"><value>true</value>indicates that the process will be awaited.</param>
        /// <returns></returns>
        private static int ExecuteCommand(string command, string args, out string stdout, out string stderr, bool waitForCompletion = true)
        {
            try
            {
                //// Check if running under admin context.
                //if (!UserIsAdmin())
                //{
                //    // Restart program and run as an admin.
                //    var exeName = Process.GetCurrentProcess().MainModule.FileName;
                //    var startInfo = new ProcessStartInfo(exeName)
                //    {
                //        Verb = "runas",
                //        CreateNoWindow = true,
                //        WindowStyle = ProcessWindowStyle.Hidden
                //    };
                //    // fire of the new process
                //    Process.Start(startInfo);
                //    // Kill the current one
                //    Environment.Exit(-1);
                //}

                // Start process and redirect stdout/in so the new spawned process gets the args.
                // Shell execute must be false so we can redirect stdxxxx
                var psi = new ProcessStartInfo(command)
                {
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                };

                var proc = Process.Start(psi);
                var sw = proc?.StandardInput;
                var sr = proc?.StandardOutput;
                var se = proc?.StandardError;

                sw?.WriteLine(args);
                sw?.Close();
                stdout = sr?.ReadToEnd();
                stderr = se?.ReadToEnd();

                // Wait for the process to complete...
                if (waitForCompletion)
                    proc?.WaitForExit();

                return proc?.ExitCode ?? -1;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }
        #endregion
    }
}
