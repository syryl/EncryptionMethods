using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DSA_Method.DSA.Library
{
    public class DSAHandler
    {
        private readonly string _hashAlgorithm = "SHA256";
        private RSAParameters publicKey;
        private RSAParameters privateKey;

        public void CreateNewKey()
        {
            using var rsaProvider = new RSACryptoServiceProvider(2048);
                rsaProvider.PersistKeyInCsp = false;
                publicKey = rsaProvider.ExportParameters(false);
                privateKey = rsaProvider.ExportParameters(true);
        }

        public byte[] SignData(byte[] hashOfDataToSign)
        {
            using var rsaProvider = new RSACryptoServiceProvider(2048);
                rsaProvider.PersistKeyInCsp = false;
                rsaProvider.ImportParameters(privateKey);

                RSAPKCS1SignatureFormatter rsaFormatter = new RSAPKCS1SignatureFormatter(rsaProvider);
                rsaFormatter.SetHashAlgorithm(_hashAlgorithm);

                return rsaFormatter.CreateSignature(hashOfDataToSign);
        }

        public bool VerifySignature(byte[] hashOfDataToSign, byte[] signature)
        {
            using var rsaProvider = new RSACryptoServiceProvider(2048);
                rsaProvider.ImportParameters(publicKey);

                RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsaProvider);
                rsaDeformatter.SetHashAlgorithm(_hashAlgorithm);

                return rsaDeformatter.VerifySignature(hashOfDataToSign, signature);
        }
    }
}
