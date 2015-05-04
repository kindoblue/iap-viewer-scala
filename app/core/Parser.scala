package core

import Common.using

import java.io.InputStream
import java.net.URL

import org.bouncycastle.asn1._
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.cms.CMSSignedData

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

  private def parsePurchaseField(field: Any) = {
    val fieldType = field.asInstanceOf[DLSequence].getObjectAt(0) match {
      case zz: ASN1Integer => zz.getValue.intValue
      case _ => throw new ClassCastException("Expected an integer as field type")
    }
    val fieldValue = field.asInstanceOf[DLSequence].getObjectAt(2) match {
      case z2: ASN1OctetString => ASN1Primitive.fromByteArray(z2.getOctets)
      case _ => throw new ClassCastException("Expected an ASN1OctetString as field value")
    }
    val f = fieldValue match {
      case s: DERUTF8String => s.getString
      case z: ASN1Integer => z.getValue.intValue
      case d: DERIA5String =>  d.getString
      case _ =>   throw new ClassCastException("Field value not expected")
    }
    fieldType match {
      case 1701 => Map("quantity" -> f)
      case 1702 => Map("product-id" -> f)
      case 1703 => Map("transaction-id" -> f)
      case 1704 => Map("purchase-date" -> f)
      case 1705 => Map("org-transaction-id" -> f)
      case 1706 => Map("org-purchase-date" -> f)
      case 1708 => Map("subscription-exp-date" -> f)
      case 1712 => Map("cancellation-date" -> f)
      case _ => Map()
    }
  }

  private def parsePurchase(purchase: Any)  = {
    val dlSeq = purchase match {
      case z: DLSequence => z.getObjectAt(2)
      case _ => throw new ClassCastException("Expected a DLSequence as a purchase record")
    }
    val fieldSet = dlSeq match  {
      case z2: ASN1OctetString => ASN1Primitive.fromByteArray(z2.getOctets)
      case _ => throw new ClassCastException
    }

    // get the iterator on fields
    val fieldIterator : Iterator[Any] = fieldSet.asInstanceOf[ASN1Set].getObjects.asScala

    // reduce to a single map with a key for every field
    fieldIterator.map(parsePurchaseField).reduce(_++_)

  }

  /**
   * It takes an object and verifies if it is a purchase record
   *
   * @param maybePurchase
   * @return true if the input is a purchase record
   */
  private def isPurchase(maybePurchase: Any) : Boolean = {
    val dlSeq = maybePurchase match {
      case z: DLSequence => z
      case _ => throw new ClassCastException("Expected a DLSequence as a purchase record")
    }
    val a = dlSeq.getObjectAt(0)  match {
      case purchaseTag: ASN1Integer => purchaseTag.getValue.intValue
      case _ => throw new ClassCastException("Expected an integer as field id in receipt")
    }

    val b = dlSeq.getObjectAt(1)  match {

      case zz: ASN1Integer => zz.getValue.intValue
      case _ => throw new ClassCastException("Expected an integer as field id in receipt")
    }

    a  == 17 && b == 1
  }

  private def getSignedData(stream: InputStream): CMSSignedData = {

    // create an asn1 stream
    val asn1Stream = new ASN1InputStream(stream)

    // read object from asn1 stream and create the content info
    // out of it
    val contentInfo =  ContentInfo.getInstance(asn1Stream.readObject())

    // create the cms signed data object out of content info object
    new CMSSignedData(contentInfo)
  }

  private def getContentIterator(signedData: CMSSignedData) : Iterator[Any] = {

    // retrieve the byte array of the signed content and create a
    // ASN1Primitive generic object out of it
    val asn1Set : ASN1Primitive = signedData.getSignedContent.getContent match  {
      case z2: Array[Byte] => ASN1Primitive.fromByteArray(z2)
      case _ => throw new ClassCastException("An ASN1 primitive object could not be created from the signed content")
    }

    // if the asn1 set is correctly retrieved, we return the scala iterator
    asn1Set match {
      case ff2: ASN1Set => ff2.getObjects.asScala
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
  def parsePurchasesFromURL(receiptUrl: URL) : Try[List[Map[_ <: String, Any]]]= {


    // error handling with monadic approach (Try and for comprehension)

    for {

      // get the raw entries as iterator
      rawEntries <- Try {

        // open the receipt stream using the loan pattern
        // get the signed data and then the content iterator
        using(receiptUrl.openStream()) {

          stream => {

            // get the signed data
            val signedData = getSignedData(stream)

            // return the content iterator
            getContentIterator(signedData)
          }
        }
      }

      // filter the raw entries, get only the purchases, parse them and
      // return them as a list of maps
      purchases <- Try(rawEntries.filter(isPurchase).map(parsePurchase).toList)

    } yield purchases


  } // end of parsePurchasesFromURL

}
