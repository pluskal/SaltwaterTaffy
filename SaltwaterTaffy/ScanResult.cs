using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Simple.DotNMap;

namespace SaltwaterTaffy
{
    /// <summary>
    ///     Represents the result of an nmap run
    /// </summary>
    public class ScanResult
    {
        /// <summary>
        ///     Use the provided raw nmaprun object to construct a more sane ScanResult object which contains information about the
        ///     nmap run
        /// </summary>
        /// <param name="result">The result of parsing an nmaprun </param>
        public ScanResult(nmaprun result)
        {
            this.Total = int.Parse(result.runstats.hosts.total);
            this.Up = int.Parse(result.runstats.hosts.up);
            this.Down = int.Parse(result.runstats.hosts.down);
            this.Hosts = result.Items != null
                ? result.Items.OfType<host>().Select(
                    x => new Host
                    {
                        Address = IPAddress.Parse(x.address.addr),
                        Ports =
                            PortsSection(
                                x.Items.OfType<ports>().DefaultIfEmpty(null).FirstOrDefault()),
                        ExtraPorts =
                            ExtraPortsSection(
                                x.Items.OfType<ports>().DefaultIfEmpty(null).FirstOrDefault()),
                        Hostnames =
                            HostnamesSection(
                                x.Items.OfType<hostnames>().DefaultIfEmpty(null).FirstOrDefault()),
                        OsMatches = OsMatchesSection(
                            x.Items.OfType<os>().DefaultIfEmpty(null).FirstOrDefault())
                    })
                : Enumerable.Empty<Host>();
        }

        public int Total { get; set; }
        public int Up { get; set; }
        public int Down { get; set; }
        public IEnumerable<Host> Hosts { get; set; }

        /// <summary>
        ///     Process the "ports" section of the XML document
        /// </summary>
        /// <param name="portsSection">Object representing the ports section</param>
        /// <returns>A collection of Port objects containing information about each individual port</returns>
        private static IEnumerable<Port> PortsSection(ports portsSection)
        {
            return portsSection != null && portsSection.port != null
                ? portsSection.port.Select(
                    x => new Port
                    {
                        PortNumber = int.Parse(x.portid),
                        Protocol = x.protocol != portProtocol.sctp
                            ? (ProtocolType)
                            Enum.Parse(typeof(ProtocolType),
                                x.protocol == portProtocol.ip
                                    ? x.protocol.ToString().ToUpperInvariant()
                                    : x.protocol.ToString().Capitalize())
                            : ProtocolType.Unknown,
                        Filtered = x.state.state1 == "filtered",
                        Service = x.service != null
                            ? new Service
                            {
                                Name = x.service.name,
                                Product = x.service.product,
                                Os = x.service.ostype,
                                Version = x.service.version
                            }
                            : default(Service)
                    }
                )
                : Enumerable.Empty<Port>();
        }

        /// <summary>
        ///     Process the "extraports" section of the XML document (contains large numbers of ports in the same state)
        /// </summary>
        /// <param name="portsSection">Object representing the ports section</param>
        /// <returns>A collection of ExtraPorts objects if the extraports section exists, empty otherwise</returns>
        private static IEnumerable<ExtraPorts> ExtraPortsSection(ports portsSection)
        {
            return portsSection != null && portsSection.extraports != null
                ? portsSection.extraports.Select(
                    x => new ExtraPorts
                    {
                        Count = int.Parse(x.count),
                        State = x.state
                    })
                : Enumerable.Empty<ExtraPorts>();
        }

        /// <summary>
        ///     Process the "hostnames" section of the XML document
        /// </summary>
        /// <param name="names">Object representing the hostnames section</param>
        /// <returns>A collection of hostnames as strings if the hostname exists, empty otherwise</returns>
        private static IEnumerable<string> HostnamesSection(hostnames names)
        {
            return names != null && names.hostname != null
                ? names.hostname.Select(x => x.name)
                : Enumerable.Empty<string>();
        }

        /// <summary>
        ///     Process the "os" section of the XML document
        /// </summary>
        /// <param name="osSection">Object representing the hos section</param>
        /// <returns>A collection of Os objects if osmatch is not null, empty otherwise</returns>
        private static IEnumerable<Os> OsMatchesSection(os osSection)
        {
            return osSection != null && osSection.osmatch != null
                ? osSection.osmatch.Select(
                    x => new Os
                    {
                        Certainty = int.Parse(x.accuracy),
                        Name = x.name,
                        Family = x.osclass[0].osfamily,
                        Generation = x.osclass[0].osgen
                    })
                : Enumerable.Empty<Os>();
        }
    }
}