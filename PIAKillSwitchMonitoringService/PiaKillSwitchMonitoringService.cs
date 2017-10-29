#region Usings
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Timers;
using FirewallTesting; 
#endregion

#region Things to consider/reference...
/*
 netsh args : https://technet.microsoft.com/en-us/library/dd734783(v=ws.10).aspx 
 Change outbound connections behaviour in windows advanced firewall to blocked for all used profiles.
 Set PIA client to use tcp and port 443
 The ports we need for connection are 110, 443, 9201.
*/
#endregion

namespace PIAKillSwitchMonitoringService
{
    #region PIA Kill Switch Monitoring Service
    /// <inheritdoc />
    /// <summary>
    /// A service monitoring PIA Client executable.
    /// If the executable isn;t or stops running traffic is blocked.
    /// </summary>
    public partial class PiaKillSwitchMonitoringService : ServiceBase
    {
        #region Variables/API's
        /// Pinvoke
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetServiceStatus(IntPtr handle, ref ServiceStatus serviceStatus);

        // Holds a list with all rules we need
        private static readonly List<FirewallRule> FirewallRules = new List<FirewallRule>();

        private static Timer _timer;

        private static bool _piaClientRunningStatus = IsAlreadyRunning();
        #endregion

        #region Ctor
        public PiaKillSwitchMonitoringService()
        {
            InitializeComponent();

            CreateTimer();
        }
        #endregion

        #region Service Start
        /// <inheritdoc />
        /// <summary>
        /// Service Start
        /// </summary>
        /// <param name="args"></param>
        protected override void OnStart(string[] args)
        {
            UpdateServiceStatus(ServiceState.SERVICE_START_PENDING);

            evntLog.WriteEntry($"{ServiceName} is starting...", EventLogEntryType.Information);

            UpdateServiceStatus(ServiceState.SERVICE_RUNNING);

            evntLog.WriteEntry($"{ServiceName} has started.", EventLogEntryType.Information);

            CreateKillSwitchRules();

            evntLog.WriteEntry("Activating Kill Switch.", EventLogEntryType.Information);

            EnableKillSwitch(FirewallRules, !IsAlreadyRunning());

            evntLog.WriteEntry("Monitoring started.", EventLogEntryType.Information);

            _timer.Enabled = true;
        }
        #endregion

        #region Service Stop
        /// <inheritdoc />
        /// <summary>
        /// Service Stop
        /// </summary>
        protected override void OnStop()
        {
            UpdateServiceStatus(ServiceState.SERVICE_STOP_PENDING);

            evntLog.WriteEntry($"{ServiceName} is stopping...", EventLogEntryType.Information);

            EnableKillSwitch(FirewallRules, true);

            UpdateServiceStatus(ServiceState.SERVICE_STOPPED);

            evntLog.WriteEntry($"{ServiceName} has stopped.", EventLogEntryType.Information);
        }
        #endregion

        #region Service status updates
        /// <summary>
        /// Service status update
        /// </summary>
        /// <param name="serviceState">The service state.</param>
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
        #endregion

        #region PIAClient running check
        /// <summary>
        /// Checks if the pia service and pia client are running
        /// </summary>
        /// <returns><value>True</value>If they are runnning.</returns>
        private static bool IsAlreadyRunning()
        {
            return Process.GetProcessesByName("pia_manager").Any();
        }
        #endregion

        #region Create Timer
        /// <summary>
        /// Create a timer that we can use to fire events.
        /// </summary>
        private void CreateTimer()
        {
            // Create a timer with a 50ms interval.
            _timer = new Timer(50) { Enabled = false };

            // Elapsed event for the timer.
            _timer.Elapsed += OnTimedEvent;
        }
        #endregion

        #region Timer Events
        /// <summary>
        /// Timer's event
        /// </summary>
        /// <param name="source">The source</param>
        /// <param name="e">The args</param>
        private void OnTimedEvent(object source, ElapsedEventArgs e)
        {
            var currentPiaClientRunningStatus = IsAlreadyRunning();

            if (currentPiaClientRunningStatus == _piaClientRunningStatus) return;

            evntLog.WriteEntry($"PIA Client/Service status is: { (IsAlreadyRunning() ? "Running" : "Stopped") }.");

            EnableKillSwitch(FirewallRules, !currentPiaClientRunningStatus);

            _piaClientRunningStatus = currentPiaClientRunningStatus;
        }
        #endregion

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
        private void CreateKillSwitchRules()
        {
            evntLog.WriteEntry("Creating firewall rules...");

            AddFirewallRule(new List<FirewallRule>()
            {
                new FirewallRule() { Action = FirewallRuleParams.Action.Block, Dir = FirewallRuleParams.Direction.Out, InterfaceType = FirewallRuleParams.InterfaceType.Any, Program = "all", Localport = "all ports", Remoteport = "all ports", Protocol = FirewallRuleParams.ProtocolType.Any, Profile = FirewallRuleParams.Profile.Any, Enabled = true, Name = "#All Blocked"},
            });
        }

        #endregion

        #region CleanUpExistingRules
        /// <summary>
        /// Removes existing rules with same rule name.
        /// </summary>
        private void CleanUpFirewallRules()
        {
            evntLog.WriteEntry("Removing existing rules.");

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
        private void EnableKillSwitch(IEnumerable<FirewallRule> firewallRules, bool enabled)
        {
            CleanUpFirewallRules();

            evntLog.WriteEntry($"Kill switch active: {enabled}.");

            foreach (var firewallRule in firewallRules)
            {
                var args = string.Empty;
                var ret = default(int);
                var stdout = string.Empty;
                var stderr = string.Empty;

                // if kill switch is disabled reverse rule enabled
                firewallRule.Enabled = enabled;

                // Return a netsh valid value for enabled
                var enable = firewallRule.Enabled ? "yes" : "no";

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
                               $"enable={enable} " +
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

        #region CheckIfUserIsAdmin
        /// <summary>
        /// Checks if currently logged in user is an admin.
        /// </summary>
        /// <returns></returns>
        private static bool UserIsAdmin()
        {
            // Are we an admin, cause if we are no canges will be made!
            return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        }
        #endregion

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
        private int ExecuteCommand(string command, string args, out string stdout, out string stderr, bool waitForCompletion = true)
        {
            try
            {

                evntLog.WriteEntry("Executing command.");

                // Check if running under admin context.
                if (!UserIsAdmin())
                {
                    // Restart program and run as an admin.
                    var exeName = Process.GetCurrentProcess().MainModule.FileName;
                    var startInfo = new ProcessStartInfo(exeName)
                    {
                        Verb = "runas",
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden
                    };
                    // fire of the new process
                    Process.Start(startInfo);
                    // Kill the current one
                    Environment.Exit(-1);
                }

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
    #endregion
}