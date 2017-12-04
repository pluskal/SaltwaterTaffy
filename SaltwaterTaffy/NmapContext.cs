using System;
using System.Diagnostics;
using System.IO;
using Simple.DotNMap;
using Simple.DotNMap.Extensions;

namespace SaltwaterTaffy
{
    /// <summary>
    ///     A class that represents an nmap run
    /// </summary>
    public class NmapContext
    {
        /// <summary>
        ///     By default we try to find the path to the nmap executable by searching the path, the output XML file is a temporary file, and the nmap options are empty.
        /// </summary>
        public NmapContext()
        {
            this.Path = this.GetPathToNmap();
            this.OutputPath = System.IO.Path.GetTempFileName();
            this.Options = new NmapOptions();
        }

        /// <summary>
        ///     The path to the nmap executable
        /// </summary>
        public string Path { get; set; }

        /// <summary>
        ///     The output path for the nmap XML file
        /// </summary>
        public string OutputPath { get; set; }

        /// <summary>
        ///     The specified nmap options
        /// </summary>
        public NmapOptions Options { get; set; }

        /// <summary>
        ///     The intended target
        /// </summary>
        public string Target { get; set; }

        /// <summary>
        ///     This searches our PATH environment variable for a particular file
        /// </summary>
        /// <param name="filename">The file to search for</param>
        /// <returns>The path to the file if it is found, the empty string otherwise</returns>
        private static string LocateExecutable(string filename)
        {
            string path = Environment.GetEnvironmentVariable("path");
            string[] folders = path.Split(';');

            foreach (string folder in folders)
            {
                string combined = System.IO.Path.Combine(folder, filename);
                if (File.Exists(combined))
                {
                    return combined;
                }
            }

            return string.Empty;
        }

        /// <summary>
        ///     This searches our PATH for the nmap executable
        /// </summary>
        /// <returns>The path to the nmap exsecutable or the empty string if it cannot be located</returns>
        public string GetPathToNmap()
        {
            return LocateExecutable("nmap.exe");
        }

        /// <summary>
        ///     Execute an nmap run with the specified options on the intended target, writing the resultant XML to the specified file
        /// </summary>
        /// <returns>An nmaprun object representing the result of an nmap run</returns>
        public virtual nmaprun Run()
        {
            if (string.IsNullOrEmpty(this.OutputPath))
            {
                throw new ApplicationException("Nmap output file path is null or empty");
            }

            if (string.IsNullOrEmpty(this.Path) || !File.Exists(this.Path))
            {
                throw new ApplicationException("Path to nmap is invalid");
            }

            if (string.IsNullOrEmpty(this.Target))
            {
                throw new ApplicationException("Attempted run on empty target");
            }

            if (this.Options == null)
            {
                throw new ApplicationException("Nmap options null");
            }

            this.Options[NmapFlag.XmlOutput] = this.OutputPath;

            using (var process = new Process())
            {
                process.StartInfo.FileName = this.Path;
                process.StartInfo.Arguments = string.Format("{0} {1}", this.Options, this.Target);
                process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                process.Start();
                process.WaitForExit();

                if (!File.Exists(this.OutputPath))
                {
                    throw new NmapException(process.StartInfo.Arguments);
                }
            }

            return Serialization.DeserializeFromFile<nmaprun>(this.OutputPath);
        }
    }
}