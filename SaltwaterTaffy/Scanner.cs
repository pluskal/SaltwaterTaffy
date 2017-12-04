// This file is part of SaltwaterTaffy, an nmap wrapper library for .NET
// Copyright (C) 2013 Thom Dixon <thom@thomdixon.org>
// Released under the GNU GPLv2 or any later version

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.NetworkInformation;

namespace SaltwaterTaffy
{
    /// <summary>
    ///     High-level scanner object for performing network reconnaissance using nmap
    /// </summary>
    public class Scanner
    {
        private readonly Dictionary<ScanType, NmapFlag> _scanTypeToNmapFlag = new Dictionary<ScanType, NmapFlag>
        {
            {ScanType.Null, NmapFlag.TcpNullScan},
            {ScanType.Fin, NmapFlag.FinScan},
            {ScanType.Xmas, NmapFlag.XmasScan},
            {ScanType.Syn, NmapFlag.TcpSynScan},
            {ScanType.Connect, NmapFlag.ConnectScan},
            {ScanType.Ack, NmapFlag.AckScan},
            {ScanType.Window, NmapFlag.WindowScan},
            {ScanType.Maimon, NmapFlag.MaimonScan},
            {ScanType.SctpInit, NmapFlag.SctpInitScan},
            {ScanType.SctpCookieEcho, NmapFlag.CookieEchoScan},
            {ScanType.Udp, NmapFlag.UdpScan}
        };

        /// <summary>
        ///     Create a new scanner with an intended target
        /// </summary>
        /// <param name="target">Intended target</param>
        public Scanner(Target target)
        {
            this.Target = target;
        }

        /// <summary>
        ///     Intended target.
        /// </summary>
        public Target Target { get; set; }

        /// <summary>
        ///     NmapOptions that should persist between runs (e.g., --exclude foobar)
        /// </summary>
        public NmapOptions PersistentOptions { get; set; }

        /// <summary>
        ///     Create a new NmapContext with the intended target and our persistent options
        /// </summary>
        /// <returns>NmapContext with the intended target and our persistent options</returns>
        private NmapContext GetContext()
        {
            if (!NetworkInterface.GetIsNetworkAvailable())
                throw new ApplicationException("No network reachable");

            var ctx = new NmapContext
            {
                Target = this.Target.ToString()
            };

            if (this.PersistentOptions != null)
                ctx.Options.AddAll(this.PersistentOptions);

            return ctx;
        }

        public IEnumerable<Host> HostDiscoveryArp()
        {
            var ctx = this.GetContext();
            ctx.Options.AddAll(new[]
            {
                NmapFlag.PingScan,
                NmapFlag.ArpPingNetmaskDiscovery
            });

            return new ScanResult(ctx.Run()).Hosts;
        }


        public IEnumerable<Host> HostDiscoveryIcmp()
        {
            var ctx = this.GetContext();
            ctx.Options.AddAll(new[]
            {
                NmapFlag.PingScan,
                NmapFlag.IcmpEchoDiscovery
            });

            return new ScanResult(ctx.Run()).Hosts;
        }

        /// <summary>
        ///     Perform host discovery and OS detection on the intended target (preferably a subnet or IP range)
        /// </summary>
        /// <returns>A collection of Hosts detailing the results of the discovery</returns>
        public IEnumerable<Host> HostDiscovery()
        {
            var ctx = this.GetContext();
            ctx.Options.AddAll(new[]
            {
                NmapFlag.TcpSynScan,
                NmapFlag.OsDetection
            });

            return new ScanResult(ctx.Run()).Hosts;
        }

        /// <summary>
        ///     Determine whether the intended target is firewalled.
        /// </summary>
        /// <returns>
        ///     Returns true if the intended targer is firewalled and false otherwise. If used on a subnet or IP range, this
        ///     determines if any host has a firewall.
        /// </returns>
        public bool FirewallProtected()
        {
            var ctx = this.GetContext();
            ctx.Options.AddAll(new[]
            {
                NmapFlag.AckScan,
                NmapFlag.FragmentPackets
            });

            var sr = new ScanResult(ctx.Run());

            return
                sr.Hosts.Any(
                    x =>
                        x.ExtraPorts.First().Count > 0 && x.ExtraPorts.First().State == "filtered" ||
                        x.Ports.Any(y => y.Filtered));
        }

        /// <summary>
        ///     Build an nmap context with the specified options
        /// </summary>
        /// <param name="scanType">The desired type of scan to perform</param>
        /// <param name="ports">The ports to scan (null of empty for default ports)</param>
        /// <returns>An nmap context for performing the desired scan</returns>
        private NmapContext _portScanCommon(ScanType scanType, string ports)
        {
            var ctx = this.GetContext();
            
            // Add the appropriate flag if we're not performing a default scan
            if (scanType != ScanType.Default)
                ctx.Options.Add(this._scanTypeToNmapFlag[scanType]);
            
            // If we have a port specification, then use it
            if (!string.IsNullOrEmpty(ports))
                ctx.Options.Add(NmapFlag.PortSpecification, ports);

            return ctx;
        }

        /// <summary>
        ///     Perform a TCP port scan with service detection and OS detection.
        /// </summary>
        /// <returns>A ScanResult object detailing the results of the port scan</returns>
        public ScanResult PortScan()
        {
            var ctx = this._portScanCommon(ScanType.Default, null);
            return new ScanResult(ctx.Run());
        }

        /// <summary>
        ///     Perform the desired scan with service detection and OS detection.
        /// </summary>
        /// <returns>A ScanResult object detailing the results of the port scan</returns>
        public ScanResult PortScan(ScanType scanType)
        {
            var ctx = this._portScanCommon(scanType, null);
            return new ScanResult(ctx.Run());
        }

        /// <summary>
        ///     Perform a TCP port scan on the specified ports with service detection and OS detection.
        /// </summary>
        /// <param name="scanType">The type of scan to perform</param>
        /// <param name="ports">A list of ports to scan</param>
        /// <returns>A ScanResult object detailing the results of the port scan</returns>
        public ScanResult PortScan(ScanType scanType, IEnumerable<int> ports)
        {
            var ctx = this._portScanCommon(scanType,
                string.Join(",",
                    ports.Select(x => x.ToString(CultureInfo.InvariantCulture))));
            return new ScanResult(ctx.Run());
        }

        /// <summary>
        ///     Perform a TCP port scan on the specified ports with service detection and OS detection.
        /// </summary>
        /// <param name="scanType">The type of scan to perform</param>
        /// <param name="ports">A string detailing which ports to scan (e.g., "10-20,33")</param>
        /// <returns>A ScanResult object detailing the results of the port scan</returns>
        public ScanResult PortScan(ScanType scanType, string ports)
        {
            var ctx = this._portScanCommon(scanType, ports);
            return new ScanResult(ctx.Run());
        }

        /// <summary>
        ///     Yield a list of our own network interfaces (first half of nmap --iflist)
        /// </summary>
        /// <returns>A list of our network interfaces</returns>
        public NetworkInterface[] GetAllHostNetworkInterfaces()
        {
            return NetworkInterface.GetAllNetworkInterfaces();
        }

    }
}