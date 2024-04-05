using System.Security.Cryptography;

namespace GenerateSharedSecret
{
    public class GenerateKeys
    {
        public GenerateKeys()
        {

        }
        public KeyPair GeneratePublicPrivateKeys()
        {
            ECDsa ecdsa = ECDsa.Create();
            byte[] publicKey = ecdsa.ExportSubjectPublicKeyInfo();
            byte[] privateKey = ecdsa.ExportPkcs8PrivateKey();
            var keyPairObj = new KeyPair()
            {   
                PrivateKey = Convert.ToBase64String(privateKey),
                PublicKey = Convert.ToBase64String(publicKey)
            };

            return keyPairObj;
        }
        public string GenerateSharedSecret(string privateKey, string publicKey)
        {
            try
            {
                ECDiffieHellmanCng ecdh = new ECDiffieHellmanCng();
                ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                ecdh.HashAlgorithm = CngAlgorithm.Sha256;
                // Import private key
                ecdh.ImportPkcs8PrivateKey(ConvertBase64ToByteArray(privateKey), out _);
                // Derive shared secret as a byte array
                ECDiffieHellmanCng publicKeyProvider = new ECDiffieHellmanCng();
                publicKeyProvider.ImportSubjectPublicKeyInfo(ConvertBase64ToByteArray(publicKey), out _);
                ECDiffieHellmanPublicKey pubKey = publicKeyProvider.PublicKey;
                byte[] sharedSecretBytes = ecdh.DeriveKeyMaterial(pubKey);
                return Convert.ToBase64String(sharedSecretBytes);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error generating shared secret: " + ex.Message);
                return null;
            }
        }

        public string EncryptWithAESGCM(string plainText, string key)
        {
            Aes aesAlg = Aes.Create();
            aesAlg.Mode = CipherMode.CBC; // Use CBC mode for AES
            aesAlg.Padding = PaddingMode.PKCS7; // Use PKCS7 padding

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(ConvertBase64ToByteArray(key), aesAlg.IV);

            using (MemoryStream memoryStream = new MemoryStream())
            {
                memoryStream.Write(aesAlg.IV, 0, aesAlg.IV.Length); // Write IV to the beginning of the stream
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                {
                    streamWriter.Write(plainText);
                }
                return Convert.ToBase64String(memoryStream.ToArray());
            }
        }
        public string DecryptWithAESGCM(string cipherText, string key)
        {
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);
            byte[] keyBytes = Convert.FromBase64String(key);

            Aes aesAlg = Aes.Create();
            aesAlg.Key = keyBytes;
            aesAlg.Mode = CipherMode.CBC; // Use CBC mode for AES
            aesAlg.Padding = PaddingMode.PKCS7; // Use PKCS7 padding

            byte[] iv = new byte[aesAlg.BlockSize / 8]; // IV size based on block size
            Array.Copy(cipherTextBytes, iv, iv.Length); // Extract IV from the beginning of the ciphertext

            aesAlg.IV = iv;

            using (MemoryStream memoryStream = new MemoryStream(cipherTextBytes, iv.Length, cipherTextBytes.Length - iv.Length))
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aesAlg.CreateDecryptor(), CryptoStreamMode.Read))
            using (StreamReader streamReader = new StreamReader(cryptoStream))
            {
                return streamReader.ReadToEnd();
            }
        }

        private static byte[] ConvertBase64ToByteArray(string arrayString)
        {
            byte[] byteArray = Convert.FromBase64String(arrayString);
            return byteArray;
        }
    }

    public class KeyPair
    {
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
    }
}
