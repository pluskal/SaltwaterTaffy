using System.Net.Sockets;

namespace SaltwaterTaffy
{
    /// <summary>
    ///     Struct representing a port on a host
    /// </summary>
    public struct Port
    {
        public int PortNumber { get; set; }
        public ProtocolType Protocol { get; set; }
        public bool Filtered { get; set; }
        public Service Service { get; set; }
        public bool Closed { get; set; }

        public override string ToString()
        {
            return $"Port {this.Protocol}/f:{this.Filtered}/c:{this.Closed}: {this.PortNumber}";
        }
    }
}