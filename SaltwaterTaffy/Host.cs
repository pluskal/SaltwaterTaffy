using System.Collections.Generic;
using System.Linq;
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
        public override string ToString()
        {
            var sb = new System.Text.StringBuilder();
            sb.Append($"Address: {this.Address}");
            if (this.Hostnames != null && this.Hostnames.Any()) { sb.Append($", {string.Join(",", this.Hostnames)}"); }
			if (this.Ports != null && this.Ports.Any()) { sb.Append($", {string.Join(",", this.Ports)}"); }
			if (this.ExtraPorts != null && this.ExtraPorts.Any()) { sb.Append($", {string.Join(",", this.ExtraPorts)}"); }
			if (this.OsMatches != null && this.OsMatches.Any()) { sb.Append($", {string.Join(",", this.OsMatches)}"); }
            return sb.ToString();
        }
    }
}