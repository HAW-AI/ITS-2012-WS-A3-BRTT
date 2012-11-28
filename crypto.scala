import java.io._
import java.security._
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec


object crypto {
  def readPrivateKey(filePath : String) : PrivateKey =
    decodePrivateKey(readEncodedKey(filePath))
    
  def readPublicKey(filePath : String) : PublicKey =
    decodePublicKey(readEncodedKey(filePath))
  
  
  private def decodePrivateKey(encodedKey : Array[Byte]) : PrivateKey = {
    val spec = new PKCS8EncodedKeySpec(encodedKey)
    val factory = KeyFactory.getInstance("RSA")
    factory.generatePrivate(spec)
  }
  
  private def decodePublicKey(encodedKey : Array[Byte]) : PublicKey = {
    val spec = new X509EncodedKeySpec(encodedKey)
    val factory = KeyFactory.getInstance("RSA")
    factory.generatePublic(spec)
  }
  
  private def readEncodedKey(filePath : String) : Array[Byte] = {
    val dataStream = new DataInputStream(new FileInputStream(filePath))
    
    val nameLength = dataStream.readInt
    dataStream.skip(nameLength)
    
    val keyLength = dataStream.readInt
    val key : Array[Byte] = Array.ofDim(keyLength)
    dataStream.read(key)
    
    dataStream.close

    key
  }
}