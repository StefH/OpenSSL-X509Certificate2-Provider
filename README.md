# OpenSSL X509Certificate2 Provider
Parses OpenSSL public and private key components and returns a **X509Certificate2** with **RSACryptoServiceProvider**. (Based on http://www.jensign.com/opensslkey/opensslkey.cs)

| Project | NuGet |
| ------- | ----- |
| OpenSSL.PrivateKeyDecoder | [![NuGet Badge](https://buildstats.info/nuget/OpenSSL.PrivateKeyDecoder)](https://www.nuget.org/packages/OpenSSL.PrivateKeyDecoder) |
| OpenSSL.X509Certificate2.Provider | [![NuGet Badge](https://buildstats.info/nuget/OpenSSL.X509Certificate2.Provider)](https://www.nuget.org/packages/OpenSSL.X509Certificate2.Provider) |

Support for the following frameworks:
* NET 2.0
* NET 3.5
* NET 4.5 and up
* NETStandard 1.3

Support for decoding `RSA Private Key` and `Private Key`.

## Example

### Generate public certificate + privatekey
Generate public certificate + privatekey using:
```
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout private.key -out certificate_pub.crt
```

### Code example 1 - decode private key
If you just want to decode the private key into a RSACryptoServiceProvider, use the following code:
```csharp
string privateKeyText = File.ReadAllText("private.key");

IOpenSSLPrivateKeyDecoder decoder = new OpenSSLPrivateKeyDecoder();
RSACryptoServiceProvider cryptoServiceProvider = decoder.Decode(privateKeyText);

// Example: sign the data
byte[] hello = new UTF8Encoding().GetBytes("Hello World");
byte[] hashValue = cryptoServiceProvider.SignData(hello, CryptoConfig.MapNameToOID("SHA256"));

// Example: use the PrivateKey from the certificate above for signing a JWT token using Jose.Jwt:
string token = Jose.JWT.Encode(payload, cryptoServiceProvider, JwsAlgorithm.RS256);
```

### Code example 2 - Create a X509 certificate and add private key
```csharp
string certificateText = File.ReadAllText("certificate_pub.crt");
string privateKeyText = File.ReadAllText("private.key");

ICertificateProvider provider = new CertificateFromFileProvider(certificateText, privateKeyText);
X509Certificate2 certificate = provider.Certificate;

// Example: use the PrivateKey from the certificate above for signing a JWT token using Jose.Jwt:
string token = Jose.JWT.Encode(payload, certificate.PrivateKey, JwsAlgorithm.RS256);
```
