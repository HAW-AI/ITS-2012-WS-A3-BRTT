import crypto._

object SendSecureFile extends App {
  if (args.length != 4) {
    println("Usage: SendSecureFile <private key file> <public key file> <in file> <out file>")
    sys.exit(1)
  }

  val privateKeyFile = args(0)
  val publicKeyFile = args(1)
  val inputFile = args(2)
  val outputFile = args(3)

  val privateKey = io.readPrivateKey(privateKeyFile)
  val publicKey = io.readPublicKey(publicKeyFile)

  val secretKey = aes.generateSecretKey
  val signature = rsa.sign(privateKey, secretKey.getEncoded)
  val encryptedSecretKey = rsa.encrypt(publicKey, secretKey.getEncoded)

  val data = io.readFile(inputFile)
  val encryptedData = aes.encrypt(secretKey, data)

  io.writeSecureFile(encryptedSecretKey, signature, encryptedData, outputFile)
}