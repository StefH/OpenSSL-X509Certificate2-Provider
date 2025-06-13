## OpenSSL X509Certificate2 Provider
Parses OpenSSL public and private key components and returns a **X509Certificate2** with **RSA/RSACryptoServiceProvider**. (Based on [http://www.jensign.com/opensslkey/opensslkey.cs (Archive Link)](https://web.archive.org/web/20171205121514/http://www.jensign.com/opensslkey/opensslkey.cs))

### Example

#### Generate public certificate + privatekey
Generate public certificate + privatekey using:
```
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout private.key -out certificate_pub.crt
```

#### Code example 1 - decode private key into RSAParameters
If you just want to decode the private key into RSAParameters, use the following code:
```csharp
string privateKeyText = File.ReadAllText("private.key");

IOpenSSLPrivateKeyDecoder decoder = new OpenSSLPrivateKeyDecoder();
RSAParameters parameters = decoder.DecodeParameters(privateKeyText);

// do something with the parameters ...
```

#### Code example 2 - decode private key into a RSACryptoServiceProvider
If you want to decode the private key into a RSACryptoServiceProvider, use the following code:
```csharp
string privateKeyText = File.ReadAllText("private.key");

IOpenSSLPrivateKeyDecoder decoder = new OpenSSLPrivateKeyDecoder();
RSACryptoServiceProvider cryptoServiceProvider = decoder.Decode(privateKeyText);

// Example: sign the data
byte[] hello = new UTF8Encoding().GetBytes("Hello World");
byte[] hashValue = cryptoServiceProvider.SignData(hello, CryptoConfig.MapNameToOID("SHA256"));

// Example: use the PrivateKey from above for signing a JWT token using Jose.Jwt:
string token = Jose.JWT.Encode(payload, cryptoServiceProvider, JwsAlgorithm.RS256);
```

#### Code example 3 - Create a X509 certificate and add private key
```csharp
string certificateText = File.ReadAllText("certificate_pub.crt");
string privateKeyText = File.ReadAllText("private.key");

ICertificateProvider provider = new CertificateFromFileProvider(certificateText, privateKeyText);
X509Certificate2 certificate = provider.Certificate;

// Example: use the PrivateKey from the certificate above for signing a JWT token using Jose.Jwt:
string token = Jose.JWT.Encode(payload, certificate.PrivateKey, JwsAlgorithm.RS256);
```

#### Code example 4 - decode openssl RSA public key into RSAParameters
If you just want to decode the rsa public key into RSAParameters, use the following code:

Export the public key from the private key with openssl
```
openssl rsa -in private.key -out public.key -pubout
```

```csharp
string publicKeyText = File.ReadAllText("public.key");

IOpenSSLPublicKeyDecoder decoder = new OpenSSLPublicKeyDecoder();
RSAParameters parameters = decoder.DecodeParameters(publicKeyText);
```

### Sponsors

[Entity Framework Extensions](https://entityframework-extensions.net/?utm_source=StefH) and [Dapper Plus](https://dapper-plus.net/?utm_source=StefH) are major sponsors and proud to contribute to the development of **OpenSSL.PrivateKeyDecoder**, **OpenSSL.PublicKeyDecoder** and **OpenSSL.X509Certificate2.Provider**.

[![Entity Framework Extensions](https://raw.githubusercontent.com/StefH/resources/main/sponsor/entity-framework-extensions-sponsor.png)](https://entityframework-extensions.net/bulk-insert?utm_source=StefH)

[![Dapper Plus](https://raw.githubusercontent.com/StefH/resources/main/sponsor/dapper-plus-sponsor.png)](https://dapper-plus.net/bulk-insert?utm_source=StefH)