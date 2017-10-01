namespace FirewallTesting
{
    public class FirewallRule
    {
        public string Name { get; set; }
        public FirewallRuleParams.Direction Dir { get; set; }
        public FirewallRuleParams.Action Action { get; set; }
        public FirewallRuleParams.ProtocolType Protocol { get; set; }
        public string Localport { get; set; }
        public string Remoteport { get; set; }
        public FirewallRuleParams.Profile Profile { get; set; }
        public FirewallRuleParams.InterfaceType InterfaceType { get; set; }
        public string Program { get; set; }
        public bool Enabled { get; set; }
    }
}