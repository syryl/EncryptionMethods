using DSA_Method.DSA.Library;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DSA_Method.DSA.Tests
{
    [TestClass]
    public class DSAHandlerTest
    {
        [TestMethod]
        public void TestDsaRandomText_ReturnTrue()
        {
            var document = Encoding.UTF8.GetBytes("Fat son how smiling mrs natural expense anxious friends. Boy scale enjoy ask abode fanny being son.");
            byte[] hashedDocument;

            using var sha256 = SHA256.Create();
                hashedDocument = sha256.ComputeHash(document);

            var digitalSignature = new DSAHandler();
            digitalSignature.CreateNewKey();

            byte[] signature = digitalSignature.SignData(hashedDocument);
            bool verified = digitalSignature.VerifySignature(hashedDocument, signature);

            Assert.IsTrue(verified);
        }
    }
}
