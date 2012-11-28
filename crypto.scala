import java.io._
import java.security._
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto._
import javax.crypto.spec.SecretKeySpec

object crypto {
  object rsa {
    def decodePrivateKey(encodedKey: Array[Byte]): PrivateKey = {
      val spec = new PKCS8EncodedKeySpec(encodedKey)
      val factory = KeyFactory.getInstance("RSA")
      factory.generatePrivate(spec)
    }

    def decodePublicKey(encodedKey: Array[Byte]): PublicKey = {
      val spec = new X509EncodedKeySpec(encodedKey)
      val factory = KeyFactory.getInstance("RSA")
      factory.generatePublic(spec)
    }

    def encrypt(key: PublicKey, data: Array[Byte]): Array[Byte] = {
      val cipher = Cipher.getInstance("RSA")
      cipher.init(Cipher.ENCRYPT_MODE, key)
      cipher.doFinal(data)
    }

    def decrypt(key: PrivateKey, data: Array[Byte]): Array[Byte] = {
      val cipher = Cipher.getInstance("RSA")
      cipher.init(Cipher.DECRYPT_MODE, key)
      cipher.doFinal(data)
    }

    def sign(key: PrivateKey, data: Array[Byte]): Array[Byte] = {
      val signature = Signature.getInstance("SHA1withRSA")
      signature.initSign(key)
      signature.update(data)
      signature.sign
    }

    def verify(key: PublicKey, signature: Array[Byte], data: Array[Byte]): Boolean = {
      val signer = Signature.getInstance("SHA1withRSA")
      signer.initVerify(key)
      signer.update(signature)
      signer.verify(data)
    }
  }

  object aes {
    def encrypt(key: SecretKey, data: Array[Byte]): Array[Byte] = {
      val cipher = Cipher.getInstance("AES")
      cipher.init(Cipher.ENCRYPT_MODE, key)
      cipher.doFinal(data)
    }

    def decrypt(key: SecretKey, data: Array[Byte]): Array[Byte] = {
      val cipher = Cipher.getInstance("AES")
      cipher.init(Cipher.DECRYPT_MODE, key)
      cipher.doFinal(data)
    }

    def generateSecretKey: SecretKey = {
      val generator = KeyGenerator.getInstance("AES")
      generator.init(128)
      generator.generateKey
    }

    def decodeSecretKey(encodedKey: Array[Byte]): SecretKey = {
      new SecretKeySpec(encodedKey, "AES")
    }
  }
  
  object io {
    def readPrivateKey(filePath: String): PrivateKey =
      rsa.decodePrivateKey(readEncodedRSAKey(filePath))

    def readPublicKey(filePath: String): PublicKey =
      rsa.decodePublicKey(readEncodedRSAKey(filePath))

    def readEncodedRSAKey(filePath: String): Array[Byte] = {
      val dataStream = new DataInputStream(new FileInputStream(filePath))

      val nameLength = dataStream.readInt
      dataStream.skip(nameLength)

      val keyLength = dataStream.readInt
      val key: Array[Byte] = Array.ofDim(keyLength)
      dataStream.read(key)

      dataStream.close

      key
    }

    def readSecureFile(filePath: String): (Array[Byte], Array[Byte], Array[Byte]) = {
      val dataStream = new DataInputStream(new FileInputStream(filePath))

      val keyLength = dataStream.readInt
      val key: Array[Byte] = Array.ofDim(keyLength)
      dataStream.read(key)

      val signatureLength = dataStream.readInt
      val signature: Array[Byte] = Array.ofDim(signatureLength)
      dataStream.read(signature)

      val dataLength = dataStream.available()
      val data: Array[Byte] = Array.ofDim(dataLength)
      dataStream.read(data)

      dataStream.close

      (key, signature, data)
    }

    def writeSecureFile(encryptedSecretKey: Array[Byte], signature: Array[Byte], encryptedData: Array[Byte], filePath: String): Unit = {
        val dataStream = new DataOutputStream(new FileOutputStream(filePath))

        dataStream.writeInt(encryptedSecretKey.length)
        dataStream.write(encryptedSecretKey)

        dataStream.writeInt(signature.length)
        dataStream.write(signature)

        dataStream.write(encryptedData)

        dataStream.close
      }
  }
}