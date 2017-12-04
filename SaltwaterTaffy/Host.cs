using System.Collections.Generic;
using System.Net;

namespace SaltwaterTaffy
{
    /// <summary>
    ///     Struct which represents a scanned host
    /// </summary>
    public struct Host
    {
        public IPAddress Address { get; set; }
        public IEnumerable<string> Hostnames { get; set; }
        public IEnumerable<Port> Ports { get; set; }
        public IEnumerable<ExtraPorts> ExtraPorts { get; set; }
        public IEnumerable<Os> OsMatches { get; set; }
    }
}