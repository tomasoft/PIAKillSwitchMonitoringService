using System.ServiceProcess;

namespace PIAKillSwitchMonitoringService
{
    public static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        public static void Main()
        {
            var servicesToRun = new ServiceBase[]
            {
                new PiaKillSwitchMonitoringService()
            };
            
            ServiceBase.Run(servicesToRun);
        }

    }
}