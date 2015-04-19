package core

import java.security.cert.X509Certificate

import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter

/**
 * Created by Stefano on 21/03/15.
 *
 * Here's the stuff needed by Parser and Validator objects
 *
 */
object Common {

  /**
   * Loan pattern for resources that has to be closed after manipulation.
   * Curried function, so we can use {} to wrap the function literal in input.
   *
   * see Programming in Scala, pag 174
   * see Beginning Scala, page 110
   *
   * @param resource the resource to handle, which has for sure a close method
   * @param f the function to perform on the resource
   * @tparam A the type of the resource. A can be an instance of any class as long
   *           as that class has a close method on it (structural type bound on A)
   * @tparam B the return type resulting from the handling of the resource
   * @return the result from f application
   */
  def using[A <: { def close(): Unit }, B](resource: A)(f: A => B): B =
    try {
      f(resource) }
    finally {
      resource.close()
    }


  /**
   * Convert a certificate from Bouncy Castle format to x509.
   * @param holder the input certificate
   * @return the certificate in x509 format
   */
  def convertX509(holder : X509CertificateHolder) : X509Certificate = {
    val converter = new JcaX509CertificateConverter().setProvider("BC")
    converter.getCertificate(holder)
  }

  /**
   * Convert a certificate from possibly a Bouncy Castle format to x509.
   * @param holder the input certificate
   * @return the certificate in x509 format
   */
  def convertX509(holder: Any) : X509Certificate = {
    val converter = new JcaX509CertificateConverter().setProvider("BC")
    converter.getCertificate(holder.asInstanceOf[X509CertificateHolder])
  }

}
