package com.tsfa.modules;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.UndeclaredThrowableException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Random;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * This is an example implementation of the OATH TOTP algorithm. Visit
 * www.openauthentication.org for more information.
 * 
 * @author Johan Rydell, PortWise, Inc.
 */

public class TOTP {

  private TOTP() {

  }

  /**
   * This method uses the JCE to provide the crypto algorithm. HMAC computes a
   * Hashed Message Authentication Code with the crypto hash algorithm as a
   * parameter.
   * 
   * @param crypto
   *          : the crypto algorithm (HmacSHA1, HmacSHA256, HmacSHA512)
   * @param keyBytes
   *          : the bytes to use for the HMAC key
   * @param text
   *          : the message or text to be authenticated
   */
  private static byte[] hmac_sha(String crypto, byte[] keyBytes, byte[] text) {

    try {
      Mac hmac;
      hmac = Mac.getInstance(crypto);
      SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
      hmac.init(macKey);
      return hmac.doFinal(text);
    } catch (GeneralSecurityException gse) {
      throw new UndeclaredThrowableException(gse);
    }
  }

  /**
   * This method converts a HEX string to Byte[]
   * 
   * @param hex
   *          : the HEX string
   * @return: a byte array
   */

  private static byte[] hexStr2Bytes(String hex) {

    // Adding one byte to get the right conversion
    // Values starting with "0" can be converted
    byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

    // Copy all the REAL bytes, not the "first"
    byte[] ret = new byte[bArray.length - 1];
    for (int i = 0; i < ret.length; i++) {
      ret[i] = bArray[i + 1];
    }
    return ret;
  }

  public static String toHex(String arg) throws UnsupportedEncodingException {

    return String.format("%x", new BigInteger(arg.getBytes()));
  }

  private static final int[] DIGITS_POWER
  // 0 1 2 3 4 5 6 7 8
  = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

  /**
   * This method generates a TOTP value for the given set of parameters.
   * 
   * @param key
   *          : the shared secret, HEX encoded
   * @param time
   *          : a value that reflects a time
   * @param returnDigits
   *          : number of digits to return
   * @return: a numeric String in base 10 that includes {@link truncationDigits}
   *          digits
   */

  public static String generateTOTP(String key, String time, String returnDigits) {

    return generateTOTP(key, time, returnDigits, "HmacSHA1");
  }

  /**
   * This method generates a TOTP value for the given set of parameters.
   * 
   * @param key
   *          : the shared secret, HEX encoded
   * @param time
   *          : a value that reflects a time
   * @param returnDigits
   *          : number of digits to return
   * @return: a numeric String in base 10 that includes {@link truncationDigits}
   *          digits
   */

  public static String generateTOTP256(String key, String time,
      String returnDigits) {

    return generateTOTP(key, time, returnDigits, "HmacSHA256");
  }

  /**
   * This method generates a TOTP value for the given set of parameters.
   * 
   * @param key
   *          : the shared secret, HEX encoded
   * @param time
   *          : a value that reflects a time
   * @param returnDigits
   *          : number of digits to return
   * @return: a numeric String in base 10 that includes {@link truncationDigits}
   *          digits
   */

  public static String generateTOTP512(String key, String time,
      String returnDigits) {

    return generateTOTP(key, time, returnDigits, "HmacSHA512");
  }

  /**
   * This method generates a TOTP value for the given set of parameters.
   * 
   * @param key
   *          : the shared secret, HEX encoded
   * @param time
   *          : a value that reflects a time
   * @param returnDigits
   *          : number of digits to return
   * @param crypto
   *          : the crypto function to use
   * @return: a numeric String in base 10 that includes {@link truncationDigits}
   *          digits
   */

  public static String generateTOTP(String key, String time,
      String returnDigits, String crypto) {

    int codeDigits = Integer.decode(returnDigits).intValue();
    String result = null;

    // Using the counter
    // First 8 bytes are for the movingFactor
    // Compliant with base RFC 4226 (HOTP)
    while (time.length() < 16) {
      time = "0" + time;
    }

    // Get the HEX in a Byte[]
    byte[] msg = hexStr2Bytes(time);
    byte[] k = hexStr2Bytes(key);

    byte[] hash = hmac_sha(crypto, k, msg);

    // put selected bytes into result int
    int offset = hash[hash.length - 1] & 0xf;

    int binary = ((hash[offset] & 0x7f) << 24)
        | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8)
        | (hash[offset + 3] & 0xff);

    int otp = binary % DIGITS_POWER[codeDigits];

    result = Integer.toString(otp);
    while (result.length() < codeDigits) {
      result = "0" + result;
    }
    return result;
  }

  public static boolean verify(String key, String value) {

    return verify(key, value, 1);
  }

  public static boolean verify(String key, String value, int offset) {

    String seed = QBase32.decode(key);

    long T0 = 0;
    long X = 30;

    long[] timeStamps = new long[(2 * offset) + 1];

    timeStamps[0] = (System.currentTimeMillis() / 1000);
    for (int i = 1; i <= offset; i++) {
      timeStamps[i * 2 - 1] = (System.currentTimeMillis() / 1000) - (X * i);
      timeStamps[i * 2] = (System.currentTimeMillis() / 1000) + (X * i);
    }

    String steps = "0";
    DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    df.setTimeZone(TimeZone.getTimeZone("UTC"));

    for (int i = 0; i < timeStamps.length; i++) {
      long T = (timeStamps[i] - T0) / X;
      steps = Long.toHexString(T).toUpperCase();
      while (steps.length() < 16) {
        steps = "0" + steps;
      }

      if (generateTOTP(seed, steps, "6", "HmacSHA1").equals(value)) {
        return true;
      }
    }

    return false;
  }

  public static String randomId() {

    return randomId(20);
  }

  public static String randomId(int secretSize) {

    int numOfScratchCodes = 5;
    int scratchCodeSize = 5;
    // Allocating the buffer
    byte[] buffer = new byte[secretSize + numOfScratchCodes * scratchCodeSize];

    // Filling the buffer with random numbers.
    // Notice: you want to reuse the same random generator
    // while generating larger random number sequences.
    new Random().nextBytes(buffer);

    byte[] secretKey = Arrays.copyOf(buffer, secretSize);
    byte[] bEncodedKey = QBase32.encode(secretKey);
    String encodedKey = new String(bEncodedKey);
    return encodedKey;
  }

  public static String getQRCodeURL(String app, String email, String secret) {

    return "https://chart.googleapis.com/chart?cht=qr&chs=200x200&chld=L&choe=UTF-8&chl"
        + "=otpauth://totp/"
        + email
        + "%3Fsecret%3D"
        + secret
        + "%26issuer%3D"
        + app;
  }

}
