import crypto._
import java.io._
import javax.crypto._
import java.security._
import javax.crypto.spec.SecretKeySpec

object ReceiveSecureFile extends App {
  if (args.length != 4) {
    println("Usage: ReceiveSecureFile <private key file> <public key file> <secret key file> <in file>")
    sys.exit(1)
  }
  
  val privateKeyFile = args(0)
  val publicKeyFile = args(1)
  val inputFile = args(2)
  val outputFile = args(3)

  val privateKey = readPrivateKey(privateKeyFile)
  val publicKey = readPublicKey(publicKeyFile)
  val (encryptedSecretKey, signature, cipherText) = readEncryptedSecretKey(inputFile)
  
  val secretKey = decodeSecretKey(rsaDecrypt(encryptedSecretKey, privateKey))
  val plainText = aesDecrypt(cipherText, secretKey)
  
  writeOutputFile(plainText, outputFile)
  
  
  def writeOutputFile(data : Array[Byte], filePath : String) : Unit = {
    val outStream = new FileOutputStream(filePath)
    outStream.write(data)
    outStream.close
  }
  
  def aesDecrypt(data : Array[Byte], key : SecretKey) : Array[Byte] = {
    val cipher = Cipher.getInstance("AES")
    cipher.init(Cipher.DECRYPT_MODE, key)
    cipher.doFinal(data)
  }
  
  def isValid(key : PublicKey, signature : Array[Byte], data : Array[Byte]) : Boolean = {
    val signer = Signature.getInstance("SHA1withRSA")
    signer.initVerify(key)
    signer.update(signature)
    signer.verify(data)
  } 
  
  def decodeSecretKey(encodedKey : Array[Byte]) : SecretKey = {
    new SecretKeySpec(encodedKey, "AES")
  }
  
  def rsaDecrypt(data : Array[Byte], key : PrivateKey) : Array[Byte] = {
    val cipher = Cipher.getInstance("RSA")
    cipher.init(Cipher.DECRYPT_MODE, key)
    cipher.doFinal(data)
  }
  
  def readEncryptedSecretKey(filePath : String) : (Array[Byte], Array[Byte], Array[Byte]) = {
    val dataStream = new DataInputStream(new FileInputStream(filePath))
    
    val keyLength = dataStream.readInt
    val key : Array[Byte] = Array.ofDim(keyLength)
    dataStream.read(key)
    
    val signatureLength = dataStream.readInt
    val signature : Array[Byte] = Array.ofDim(signatureLength)
    dataStream.read(signature)
    
    val dataLength = dataStream.available()
    val data : Array[Byte] = Array.ofDim(dataLength)
    dataStream.read(data)
    
    dataStream.close
    
    (key, signature, data)
  }
}