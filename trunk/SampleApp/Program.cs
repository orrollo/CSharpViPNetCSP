using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Infotecs.Cryptography.Info;

namespace SampleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            var infos = CryptoInfo.GetProviders();

        }
    }
}
