import org.specs2.mutable._
import core._
import validation._

class HelloWorldSpec extends Specification {

  "The 'Hello world' string" should {
    "contain 11 characters" in {
      "Hello world" must have size(11)
    }
    "start with 'Hello'" in {
      "Hello world" must startWith("Hello")
    }
    "end with 'world'" in {

      val a = getClass.getResource("/1000000101882225.cer")
      println(a)
      Parser.parsePurchasesFromURL(a).foreach(println)

      val keyPair = TestDataGenerator.generateRSAKeys()

      val cert = TestDataGenerator.generateTestCertificate("CN=Stefano", "CN=Intermediate", "CN=End cert")

      println(cert)

      "Hello world" must startWith("Hello")

    }
  }
}
