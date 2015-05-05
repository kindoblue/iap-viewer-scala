package core

import java.security.Security

import Common.using

import java.io.InputStream
import java.net.URL

import org.bouncycastle.asn1._
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.jce.provider.BouncyCastleProvider

import scala.util.Try

// see http://stackoverflow.com/questions/8301947/what-is-the-difference-between-javaconverters-and-javaconversions-in-scala
import scala.collection.JavaConverters._

/**
 * Created by Stefano on 14/02/15.
 *
 * The entry point is parsePurchasesFromURL, the only public method here.
 * This uses the monadic Try for error handling, all the rest the usual java
 * exceptions.
 *
 */

object Parser {

  /**
   * It gets a DLSequence representing a field of the purchase record,
   * then parse and return it as a Map
   *
   * The DLSequence is something like:
   *
   *    [1704, 1, #1614323031342d30322d31395431333a32363a35345a]
   *
   * where the first element is the field type, the second is the version and
   * the third is the asn1 encoded value
   *
   * @param field the DLSequence representing a purchase field
   * @return a Map representing the parsed input field
   */
  private def parsePurchaseField(field: DLSequence) : Map[String, Any] = {

    // get the field type as a plain integer
    val fieldType = field.getObjectAt(0) match {
      case zz: ASN1Integer => zz.getValue.intValue
      case _ => throw new ClassCastException("Expected an integer as field type")
    }

    // construct an ASN1primitive from the third element of the input sequence
    val fieldValue = field.getObjectAt(2) match {
      case z2: ASN1OctetString => ASN1Primitive.fromByteArray(z2.getOctets)
      case _ => throw new ClassCastException("Expected an ASN1OctetString as field value")
    }

    // interpret the field value
    val f = fieldValue match {
      case s: DERUTF8String => s.getString
      case z: ASN1Integer => z.getValue.intValue
      case d: DERIA5String =>  d.getString
      case _ =>   throw new ClassCastException("Field value not expected")
    }

    // construct the Map according the field type
    fieldType match {
      case 1701 => Map("quantity" -> f)
      case 1702 => Map("product-id" -> f)
      case 1703 => Map("transaction-id" -> f)
      case 1704 => Map("purchase-date" -> f)
      case 1705 => Map("org-transaction-id" -> f)
      case 1706 => Map("org-purchase-date" -> f)
      case 1708 => Map("subscription-exp-date" -> f)
      case 1712 => Map("cancellation-date" -> f)
      case a: Int => Map(a.toString -> f)
    }
  }

  /**
   * It gets a DLSequence representing a purchase and parses it.
   *
   * The DLSequence is something like this:
   *
   *      [17, 1, #3182014b300b020206.....]
   *
   * where the first element is the field type (always 17 for purchase record),
   * the second is the version and the third is the asn1 encoded set (of purchase fields)
   *
   * @param purchase the DLSequence representing the purchase
   * @return a Map containing all the fields of the input purchase record
   */
  private def parsePurchase(purchase: DLSequence) : Map[String, Any]  = {

    // get the asn1 representation of the purchase record
    val fieldSet : ASN1Set = purchase.getObjectAt(2) match  {
      case z2: ASN1OctetString => ASN1Primitive.fromByteArray(z2.getOctets).asInstanceOf[ASN1Set]
      case _ => throw new ClassCastException
    }

    // get the iterator on the fields of the set
    val fieldIterator : Iterator[DLSequence] = fieldSet.getObjects.asInstanceOf[java.util.Enumeration[DLSequence]].asScala

    // reduce to a single map with a key for every field
    fieldIterator.map(parsePurchaseField).reduce(_++_)

  }

  /**
   * It gets a DLSequence representing a receipt record and check if it is purchase record.
   *
   * The DLSequence is something like this:
   *
   *      [17, 1, #3182014b300b020206.....]
   *
   * where the first element is the field type (always 17 for purchase record),
   * the second is the version and the third is the asn1 encoded set (of purchase fields)
   *
   * @param maybePurchase
   * @return true if the input is a purchase record
   */
  private def isPurchase(maybePurchase: DLSequence) : Boolean = {

    // get the record type as a simple integer
    val recordType = maybePurchase.getObjectAt(0)  match {
      case purchaseTag: ASN1Integer => purchaseTag.getValue.intValue
      case _ => throw new ClassCastException("Expected an integer as field id in receipt record")
    }

    // for purchase record, the record type is 17
    recordType  == 17

  }

  /**
   * Get the signed data object from the receipt
   *
   * @param stream the stream from where to read the signed data
   * @return the signed data object
   */
  private def getSignedData(stream: InputStream): CMSSignedData = {

    // create an asn1 stream
    val asn1Stream = new ASN1InputStream(stream)

    // read object from asn1 stream and create the content info
    // out of it
    val contentInfo =  ContentInfo.getInstance(asn1Stream.readObject())

    // create the cms signed data object out of content info object
    new CMSSignedData(contentInfo)
  }

  /**
   * The signed data of a in-app purchase would be an asn1 encoded list of DLSequence's.
   * This method return an Iterator on the set of DLSequence's of the receipt
   *
   * @param signedData the signed data from the receipt
   * @return the iterator on the set of DLSequences of the receipt
   */
  private def getContentIterator(signedData: CMSSignedData) : Iterator[DLSequence] = {

    // retrieve the byte array of the signed content and create a
    // ASN1Primitive generic object out of it
    val asn1Set : ASN1Primitive = signedData.getSignedContent.getContent match  {
      case z2: Array[Byte] => ASN1Primitive.fromByteArray(z2)
      case _ => throw new ClassCastException("An ASN1 primitive object could not be created from the signed content")
    }

    // if the asn1 set is correctly retrieved, we return the scala iterator
    asn1Set match {
      case ff2: ASN1Set => ff2.getObjects.asInstanceOf[java.util.Enumeration[DLSequence]].asScala
      case _ => throw new ClassCastException("Expected an ASN1Set object as content in signed data")
    }
  }



  /**
   *
   * The entry point of the receipt parser. It gets an url to the receipt and
   * return a list of maps, one map for every purchase.
   *
   * Example for a map representing a single purchase:
   *
   * Map(transaction-id -> 1000000101874971,
   *     purchase-date -> 2014-02-19T13:26:54Z,
   *     org-transaction-id -> 1000000101874971,
   *     quantity -> 1, cancellation-date -> ,
   *     subscription-exp-date -> ,
   *     product-id -> 1_month_subscription,
   *     org-purchase-date -> 2014-02-18T16:18:09Z)
   *
   *
   * @param receiptUrl the url of the receipt
   * @return the List of purchases or Failure
   */
  def parsePurchasesFromURL(receiptUrl: URL) : Try[List[Map[String, Any]]]= {


    // error handling with monadic approach (Try and for comprehension)

    for {

      // get the signed data, using loan pattern and wrapping with a Try
      signedData <- Try { using(receiptUrl.openStream()) { getSignedData(_) }}

      // get the apple certificate, to be used as trustAnchor
      trustAnchor <- Validator.appleCACertificate()

      // validate the receipt
      validity <- Validator.isValidSignature(signedData, trustAnchor)

      // get the purchases
      purchases <- Try {

        // get the content iterator
        val content = getContentIterator(signedData)

        // and filter only the purchases, then parse and
        // return them as a list of maps
        content.filter(isPurchase).map(parsePurchase).toList
      }

    } yield purchases


  } // end of parsePurchasesFromURL


  // register the Bouncy Castle provider
  Security.addProvider(new BouncyCastleProvider)

}
