using Play.ECCrypto;
//Creeate ECDH key pair
(var ECDiffieHellmanCngPrivateKey, var ECDiffieHellmanCngPublicKey) = EcHelper.CreateEcdh();
//Sign any data with private key
var signedData = EcHelper.SignDataWithEc(ECDiffieHellmanCngPrivateKey, "Hello, world!");
//Verify the signed data with public key
var verified = EcHelper.VerifyEC(ECDiffieHellmanCngPublicKey, "Hello, world!", signedData);
