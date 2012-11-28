import java.io._
import java.security._
import javax.crypto._
import javax.crypto.spec.SecretKeySpec
import scala.io.Source

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
  
  val privateKey = readPrivateKey(privateKeyFile)
  val publicKey = readPublicKey(publicKeyFile)
  
  val secretKey = generateSecretKey
  val signature = sign(secretKey.getEncoded, privateKey)
  val encryptedSecretKey = rsaEncrypt(secretKey.getEncoded, publicKey)
  
  val plainText = fileBytes(inputFile)
  val cipherText = aesEncrypt(plainText, secretKey)
  
  writeOutputFile(encryptedSecretKey, signature, cipherText, outputFile)
  
  
  def writeOutputFile(encryptedSecretKey : Array[Byte],
                      signature : Array[Byte],
                      cipherText : Array[Byte],
                      filePath : String) : Unit =
  {
    val dataStream = new DataOutputStream(new FileOutputStream(filePath))
    
    dataStream.writeInt(encryptedSecretKey.length)
    dataStream.write(encryptedSecretKey)
    
    dataStream.writeInt(signature.length)
    dataStream.write(signature)
    
    dataStream.write(cipherText)
    
    dataStream.close
  }
    
  def aesEncrypt(data : Array[Byte], key : SecretKey) : Array[Byte] = {
    val cipher = Cipher.getInstance("AES")
    cipher.init(Cipher.ENCRYPT_MODE, key)
    cipher.doFinal(data)
  }
  
  def rsaEncrypt(data : Array[Byte], key : PublicKey) : Array[Byte] = {
    val cipher = Cipher.getInstance("RSA")
    cipher.init(Cipher.ENCRYPT_MODE, key)
    cipher.doFinal(data)
  }
  
  def sign(data : Array[Byte], key : PrivateKey) : Array[Byte] = {
    val signer = Signature.getInstance("SHA1withRSA")
    signer.initSign(key)
    signer.update(data)
    signer.sign
  }
  
  def generateSecretKey : SecretKey = {
    val generator = KeyGenerator.getInstance("AES")
    generator.init(128)
    generator.generateKey
  }
  
  
  def fileBytes(filePath : String) : Array[Byte] = {
    val source = Source.fromFile(inputFile)
    val bytes = source.map(_.toByte).toArray
    source.close
    bytes
  }
}