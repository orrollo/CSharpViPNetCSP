using System;
using System.Collections.Generic;
using Infotecs.Cryptography.ProviderParams;

namespace Infotecs.Cryptography
{
    public static class GostKeyContainer
    {
        public enum Signature
        {
            Gost34101994,
            Gost34102001,
            Gost34102012V256,
            Gost34102012V512
        }

        private static Dictionary<Signature,string> signatureOids = new Dictionary<Signature, string>()
        {
            { Signature.Gost34101994, "1.2.643.2.2.4" },
            { Signature.Gost34102001, "1.2.643.2.2.3" },
            { Signature.Gost34102012V256, "1.2.643.7.1.1.3.2" },
            { Signature.Gost34102012V512, "1.2.643.7.1.1.3.3" }
        };

        public static void Get(Signature signature, Action<IGostCrypt> procedure)
        {
            var oid = signatureOids[signature];
            if (!ProviderHelper.IsCompatible(oid)) throw new ArgumentException();
            using (var prm = ProviderHelper.ParamsForSignAlgoOid(oid))
            {
                using (var gostCrypt = new GostCrypt(prm))
                {
                    procedure(gostCrypt);
                }
            }
        }

    }
}