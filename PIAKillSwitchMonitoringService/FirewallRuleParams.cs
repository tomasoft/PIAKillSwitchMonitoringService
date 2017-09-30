namespace FirewallTesting
{
    public static class FirewallRuleParams
    {
        public enum Direction
        {
            In = 1,
            Out = 2
        }

        public enum Action
        {
            Allow = 1,
            Block = 2,
            Bypass = 4
        }

        public enum ProtocolType
        {
            Any = 1,
            Icmpv4 = 2,
            Icmpv6 = 4,
            Tcp = 8,
            Udp = 16
        }

        public enum Profile
        {
            Public = 1,
            Private = 2,
            Domain = 4,
            Any = 8
        }

        public enum InterfaceType
        {
            Any = 1,
            Wireless = 2,
            Lan = 4,
            Ras = 8
        }
    }
}