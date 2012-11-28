import java.io._
import java.security._
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto._
import javax.crypto.spec.SecretKeySpec
import scala.collection.immutable.Stream

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
      val signer = Signature.getInstance("SHA1withRSA")
      signer.initSign(key)
      signer.update(data)
      signer.sign
    }

    def verify(key: PublicKey, signature: Array[Byte], data: Array[Byte]): Boolean = {
      val verifier = Signature.getInstance("SHA1withRSA")
      verifier.initVerify(key)
      verifier.update(data)
      verifier.verify(signature)
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
      withDataInputStream(filePath) { stream =>
        val nameLength = stream.readInt
        stream.skip(nameLength)

        val keyLength = stream.readInt
        val key: Array[Byte] = Array.ofDim(keyLength)
        stream.read(key)

        key
      }
    }

    def readSecureFile(filePath: String): (Array[Byte], Array[Byte], Array[Byte]) = {
      withDataInputStream(filePath) { stream =>
        val keyLength = stream.readInt
        val key: Array[Byte] = Array.ofDim(keyLength)
        stream.read(key)

        val signatureLength = stream.readInt
        val signature: Array[Byte] = Array.ofDim(signatureLength)
        stream.read(signature)

        val dataLength = stream.available()
        val data: Array[Byte] = Array.ofDim(dataLength)
        stream.read(data)

        (key, signature, data)
      }
    }

    def writeSecureFile(encryptedSecretKey: Array[Byte], signature: Array[Byte], encryptedData: Array[Byte], filePath: String): Unit = {
      withDataOutputStream(filePath) { stream =>
        stream.writeInt(encryptedSecretKey.length)
        stream.write(encryptedSecretKey)

        stream.writeInt(signature.length)
        stream.write(signature)

        stream.write(encryptedData)
      }
    }

    def readFile(filePath: String): Array[Byte] = {
      withDataInputStream(filePath) { stream =>
        Stream.fill(stream.available)(stream.readByte).toArray
      }
    }

    def writeFile(filePath: String, data: Array[Byte]): Unit = {
      withDataOutputStream(filePath)(_.write(data))
    }

    def withDataInputStream[A](filePath: String)(f: DataInputStream => A): A = {
      val stream = new DataInputStream(new FileInputStream(filePath))
      val result = f(stream)
      stream.close
      result
    }

    def withDataOutputStream[A](filePath: String)(f: DataOutputStream => A): A = {
      val stream = new DataOutputStream(new FileOutputStream(filePath))
      val result = f(stream)
      stream.close
      result
    }
  }
}