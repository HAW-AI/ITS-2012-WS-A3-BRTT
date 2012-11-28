import java.io.FileOutputStream
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
  
  writeOutputFile(data, outputFile)
  
  
  def writeOutputFile(data : Array[Byte], filePath : String) : Unit = {
    val outStream = new FileOutputStream(filePath)
    outStream.write(data)
    outStream.close
  }
}