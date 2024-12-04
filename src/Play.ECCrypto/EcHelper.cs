using System.Security.Cryptography;
using System.Text;

namespace Play.ECCrypto;
public class EcHelper
{
    /// <summary>
    /// Returns a tuple of  ECDiffieHellman private key and public key
    /// </summary>
    /// <returns></returns>
    public static (string, string) CreateEcdh()
    {
        using (ECDiffieHellman ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
        {
            // Export public key parameters
            ECParameters publicKeyParameters = ecdh.ExportParameters(true);
            var privateKeyPem = ecdh.ExportECPrivateKeyPem();
            var publicKeyInfo = ecdh.ExportSubjectPublicKeyInfo();
            var publicKeyBase64 = Convert.ToBase64String(publicKeyInfo);
            return (privateKeyPem, publicKeyBase64);
        }
    }

    public static string SignDataWithEc(string privatePem, string data)
    {
        //using (ECDiffieHellman ecdh = ECDiffieHellman.Create())
        //{
        //    ecdh.ImportFromPem(privatePem);

        using (ECDsa ecdsa = ECDsa.Create())
        {
            ecdsa.ImportFromPem(privatePem);
            var signBytes = ecdsa.SignData(Encoding.UTF8.GetBytes(data), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            return Convert.ToBase64String(signBytes);
        }
        //}
    }

    public static bool VerifyEC(string publicKeyPem, string dataToVerify, string signedData)
    {
        using var ecdsa = ImportPublicKeyFromBase64(publicKeyPem);
        return ecdsa.VerifyData(
            Encoding.UTF8.GetBytes(dataToVerify),
            Convert.FromBase64String(signedData),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
    }
    static ECDsa ImportPublicKeyFromBase64(string base64PublicKey)
    {
        byte[] publicKeyBytes = Convert.FromBase64String(base64PublicKey);
        var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
        return ecdsa;
    }
}

