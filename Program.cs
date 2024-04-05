
using GenerateSharedSecret;

namespace GenerateSharedSecretProj
{
    public class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                GenerateKeys generateKeys = new GenerateKeys();
                //server key pair...
                Console.WriteLine("***Server Key pair***");
                Console.WriteLine("");
                Console.WriteLine("Server Public Key : ");
                var serverPKeys = generateKeys.GeneratePublicPrivateKeys();
                Console.WriteLine(serverPKeys.PublicKey);
                Console.WriteLine("");
                Console.WriteLine("Server Private Key : ");
                Console.WriteLine(serverPKeys.PrivateKey);
                Console.WriteLine("");
                Console.WriteLine("***Client Key pair***");
                Console.WriteLine("");
                Console.WriteLine("Client Public Key : ");
                var clientPKey = generateKeys.GeneratePublicPrivateKeys();
                Console.WriteLine(clientPKey.PublicKey);
                Console.WriteLine("");
                Console.WriteLine("Client Private Key : ");
                Console.WriteLine(clientPKey.PrivateKey);
                Console.WriteLine("");
                Console.WriteLine("***Shared Secret***");
                Console.WriteLine("");
                Console.WriteLine("Shared Secret : server pubkey + client secretkey ");
                var sharedSecret1 = generateKeys.GenerateSharedSecret(clientPKey.PrivateKey, serverPKeys.PublicKey);
                Console.WriteLine(sharedSecret1);
                Console.WriteLine("");
                Console.WriteLine("Shared Secret : client pubkey + server secretkey ");
                var sharedSecret2 = generateKeys.GenerateSharedSecret(serverPKeys.PrivateKey, clientPKey.PublicKey);
                Console.WriteLine(sharedSecret2);
                Console.WriteLine("");
                Console.WriteLine("***Encrypt Data using shared secret1***");
                Console.WriteLine("");
                Console.WriteLine("Enter random data :");
                string randomData = Console.ReadLine();
                var encryptedData = generateKeys.EncryptWithAESGCM(randomData, sharedSecret1);
                Console.WriteLine("Encrypted data :");
                Console.WriteLine(encryptedData);
                Console.WriteLine("");
                Console.WriteLine("***Decrypt Data using shared secret2***");
                var decryptedData = generateKeys.DecryptWithAESGCM(encryptedData, sharedSecret2);
                Console.WriteLine(decryptedData);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}
