import crypto._

object ReceiveSecureFile extends App {
  if (args.length != 4) {
    println("Usage: ReceiveSecureFile <private key file> <public key file> <secret key file> <in file>")
    sys.exit(1)
  }

  val privateKeyFile = args(0)
  val publicKeyFile = args(1)
  val inputFile = args(2)
  val outputFile = args(3)

  val privateKey = io.readPrivateKey(privateKeyFile)
  val publicKey = io.readPublicKey(publicKeyFile)
  val (encryptedSecretKey, signature, encryptedData) = io.readSecureFile(inputFile)

  val secretKey = aes.decodeSecretKey(rsa.decrypt(privateKey, encryptedSecretKey))
  val data = aes.decrypt(secretKey, encryptedData)

  if (rsa.verify(publicKey, signature, secretKey.getEncoded)) {
      io.writeFile(outputFile, data)
  } else {
    println("Could not verify signature!")
    sys.exit(2)
  }
}