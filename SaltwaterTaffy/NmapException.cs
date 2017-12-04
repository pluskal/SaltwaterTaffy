using System;

namespace SaltwaterTaffy
{
    public class NmapException : ApplicationException
    {
        public NmapException(string ex) : base(ex)
        {
        }
    }
}