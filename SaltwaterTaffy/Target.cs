using System.Collections.Generic;
using System.Net;

namespace SaltwaterTaffy
{
    /// <summary>
    ///     Object representing the target(s) of an nmap scan
    /// </summary>
    public struct Target
    {
        private readonly string _target;

        public Target(string target)
        {
            this._target = target;
        }

        public Target(IPAddress target)
        {
            this._target = target.ToString();
        }

        public Target(IEnumerable<IPAddress> target)
        {
            this._target = string.Join(" ", target);
        }

        public Target(IEnumerable<string> targets)
        {
            this._target = string.Join(" ", targets);
        }

        public override string ToString()
        {
            return this._target;
        }
    }
}