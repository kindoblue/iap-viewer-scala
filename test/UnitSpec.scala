import java.security.PrivateKey
import java.security.cert.X509Certificate

import org.specs2.mutable._
import core._
import validation._

import scala.util.{Failure, Success}

class UnitSpec extends Specification {

  val certs = TestDataGenerator.generateTestCertificates("CN=Stefano", "CN=Intermediate", "CN=End cert")

  val (root : X509Certificate, intermediate: X509Certificate, endCert: X509Certificate, privateKey: PrivateKey) = certs

  val envelope = TestDataGenerator.createSignedData("This is a test", root, intermediate, endCert, privateKey)

  val wrong = TestDataGenerator.generateSingleCertificate("CN=Wrong")


  "The Validator" should {

    "validate successfully the envelope when using the right anchor" in {

      Validator.isValidSignature(envelope, root) must beSuccessfulTry.withValue(true)

    }

    "NOT validate the envelope when using the wrong anchor" in {

      Validator.isValidSignature(envelope, wrong) must beFailedTry

    }


  }
}
