/*
 * Copyright (c) 2014 Diona Ltd.
 * All rights reserved.
 *
 * This software is the confidential and proprietary information of Diona
 * ("Confidential Information"). You shall not disclose such Confidential Information
 * and shall use it only in accordance with the terms of the license agreement you
 * entered into with Diona.
 */
package com.diona.fileReader;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

// import org.apache.commons.io.FileUtils;

import android.annotation.SuppressLint;
import android.content.Context;
import android.util.Base64;
import android.util.Log;

// import com.diona.socialworker.app.SocialWorkerSharedPreferences;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;
import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONException;

import android.app.Activity;
import android.content.Intent;

/**
 * Cipher utility class.
 */
public final class CipherUtil extends CordovaPlugin{
  // private static BootstrapProperties bootstrapProperties = BootstrapProperties.getInstance();
  public static final String ACTION_ENCRYPT_FILE = "encryptFile";
  public static final String ACTION_DECRYPT_FILE = "decryptFile";
  private static final boolean ENCRYPTION_ENABLED = true;
  private static final String ENCRYPTION_ALGORITHM = "AES";
  private static final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA1";
  private static final int KEY_SIZE = 256;
  private static final int KEY_ITERATIONS = 1;

  private static final String TAG = "CipherUtil";
  private static final String SECRET_KEY_PASSPHRASE = "!$%^&*()+=";
  private static CipherUtil instance;
  private static final int IV_LENGTH = 16;
  private static final int BUFFER_SIZE = 65536;
  private static final int SALT_LENGTH = 20;

  public byte[] usedIV = new byte[IV_LENGTH];
  public SecretKeySpec usedSecretKey = null;
  public IvParameterSpec ivspec = null;

  public CipherUtil() {
    // Do nothing
  }

  public void initialize(CordovaInterface cordova, CordovaWebView webView) {
    super.initialize(cordova, webView);
    Log.v(TAG,"Init File Reader plugin");
  }
  /**
   * 
   * @return an instance
   */
  public static CipherUtil getInstance() {
    if (instance == null) {
      instance = new CipherUtil();
    }
    return instance;
  }

  /**
   * Encrypts the given string (plaintext).
   * 
   * @param bytes
   *          byte array to be encrypted.
   * @param context
   *          context to fetch preferences.
   * @return encrypted byte array.
   */
  @SuppressLint("TrulyRandom")
  public byte[] encryptBytes(final byte[] bytes, final Context context) {

    // Transaction.checkLongRunningProcessing("encryptBytes");

    if (!ENCRYPTION_ENABLED) {
      return bytes;
    }

    byte[] encryptedTextBytes = null;
    try {
      // Derive the secret key
      final SecretKeySpec secretKey = getSecretKey(context);

      // encrypt the message
      final Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
      final IvParameterSpec ivspec = new IvParameterSpec(getIV(context));
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
      encryptedTextBytes = cipher.doFinal(bytes);
    } catch (final Exception e) {
      Log.e(TAG, ""+e);
    }
    return encryptedTextBytes;
  }

  /**
   * Decrypts a given encrypted string.
   * 
   * @param bytes
   *          encrypted string to be decrypted.
   * @param context
   *          context to fetch preferences.
   * @return the original string.
   */
  public byte[] decryptBytes(final byte[] bytes, final Context context) {
    // Transaction.checkLongRunningProcessing("decryptBytes");

    if (!ENCRYPTION_ENABLED) {
      return bytes;
    }

    byte[] decryptedTextBytes = null;
    try {
      final IvParameterSpec ivspec = new IvParameterSpec(getIV(context));
      final Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
      cipher.init(Cipher.DECRYPT_MODE, getSecretKey(context), ivspec);
      decryptedTextBytes = cipher.doFinal(bytes);

    } catch (final Exception e) {
      Log.e(TAG, "e"+e);
    }
    return decryptedTextBytes;
  }

  /**
   * Encrypts a file.
   * 
   * @param path
   *          path of the original file.
   * @param context
   *          context to fetch preferences.
   * @param encryptPath
   *          path of the encrypted file.
   */
  public void encryptFile(final String path, final String encryptPath, final Context context) {

    // Transaction.checkLongRunningProcessing("encryptFile");
    System.err.println("Path = "+path);
    System.err.println("encryptPath = "+encryptPath);
    final string encryptionPath = encryptPath+"_encrypted";
    try {
      System.err.println("EN - 1");
      // Here you read the cleartext.
      final FileInputStream fis = new FileInputStream(path);
      // This stream write the encrypted text. This stream will be wrapped by another stream.
      final FileOutputStream fos = new FileOutputStream(encryptionPath);

      final OutputStream outputStream;
      if (ENCRYPTION_ENABLED) {
        System.err.println("EN - 2");
        final SecretKeySpec secret = usedSecretKey = getSecretKey(context);
        final byte[] ivBytes = usedIV = getIV(context);
        ivspec = new IvParameterSpec(ivBytes);
        System.err.println("EN - 3");
        // Create cipher
        final Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secret, ivspec);
        System.err.println("EN - 4");
        // Wrap the output stream
        outputStream = new CipherOutputStream(fos, cipher);
        System.err.println("EN - 5");
      } else {
        outputStream = fos;
      }

      // Write bytes
      int b;
      System.err.println("EN - 6");
      final byte[] d = new byte[BUFFER_SIZE];
      while ((b = fis.read(d)) != -1) {
        outputStream.write(d, 0, b);
      }
      System.err.println("EN - 7");
      // Flush and close streams.
      outputStream.flush();
      outputStream.close();
      fis.close();
      System.err.println("EN - 8");
      System.err.println("File encrypted SUCCESSFULLY ");
      decryptFile(encryptionPath, encryptPath+"_decrypted", null);
    } catch (final Exception e) {
      Log.e(TAG, "e"+e);
    }
  }

  /**
   * Decrypts a file.
   * 
   * @param path
   *          path of the encrypted file.
   * @param decryptedPath
   *          the path where file should be decrypted.
   * @param context
   *          context to fetch preferences.
   * @param decryptAsyncTask
   *          the AsyncTask that calls this method and needs to be updated. Ignored if null.
   */
  public void decryptFile(final String path, final String decryptedPath, final Context context) {

    // Transaction.checkLongRunningProcessing("decryptFile");
    System.err.println("Path = "+path);
    System.err.println("decryptedPath = "+decryptedPath);
    try {
      final FileInputStream fis = new FileInputStream(path);
      final FileOutputStream fos = new FileOutputStream(decryptedPath);

      final InputStream inputStream;
      if (ENCRYPTION_ENABLED) {
        System.err.println("DE - 1");
//        final SecretKeySpec secret = getSecretKey(context);
        final SecretKeySpec secret = usedSecretKey;
        // Decrypt the message
        final Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        System.err.println("DE - 2");
        // cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(getIV(context)));
        cipher.init(Cipher.DECRYPT_MODE, secret, ivspec);
        System.err.println("DE - 3");
        inputStream = new CipherInputStream(fis, cipher);
        System.err.println("DE - 4");
      } else {
        inputStream = fis;
      }

      int b;
      final byte[] d = new byte[BUFFER_SIZE];
      int totalBytesWritten = 0;
      while ((b = inputStream.read(d)) != -1) {
        fos.write(d, 0, b);
        /*if (decryptAsyncTask != null) {
          totalBytesWritten += BUFFER_SIZE;
          decryptAsyncTask.updateProgress(totalBytesWritten);
        }*/
      }
      fos.flush();
      fos.close();
      inputStream.close();
      System.err.println("File decrypted SUCCESSFULLY ");
    } catch (final Exception e) {
      Log.e(TAG, "e"+e);
    }
  }

  /**
   * Decrypts a file and return the decrypted file as an array of bytes.
   * 
   * @param filePath
   *          The path to the encrypted file.
   * @param context
   *          The context for decryption.
   * @return A byte array of the decrypted file contents.
   */
  /*public byte[] decryptFile(final String filePath, final Context context) {
    try {
      // Check if the file exists
      final File encryptedFile = new File(filePath);
      if (!encryptedFile.exists()) {
        return null;
      }

      // Decrypt the file and return the bytes
      final byte[] encyptedBytes = FileUtils.readFileToByteArray(encryptedFile);
      return decryptBytes(encyptedBytes, context);
    } catch (final IOException e) {
      throw new RuntimeException("Exception occurred trying to decrypt file: " + filePath, e);
    }
  }*/

  /**
   * Generates the secret key to be used for encryption. The secret key is retrieved from the shared preferences if
   * previously calculated.
   * 
   * @return A new secret key if not previously calculated.
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   * @throws UnsupportedEncodingException
   */
  private SecretKeySpec getSecretKey(final Context context) throws NoSuchAlgorithmException, InvalidKeySpecException,
      UnsupportedEncodingException {
    // final SocialWorkerSharedPreferences sharedPreferences = SocialWorkerSharedPreferences.getInstance();
    // if (sharedPreferences.getSecretKey() == null) {
      final byte[] salt = generateRandomKeyBytes(SALT_LENGTH);
      final SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
      final PBEKeySpec spec = new PBEKeySpec(SECRET_KEY_PASSPHRASE.toCharArray(), salt, KEY_ITERATIONS, KEY_SIZE);
      final SecretKey secretKey = factory.generateSecret(spec);
      final SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), ENCRYPTION_ALGORITHM);

      // Set the value of the secret key in private shared preferences
      //sharedPreferences.setSecretKey(secretKeySpec);
      return secretKeySpec;
    /*} else {
      return sharedPreferences.getSecretKey();
    }*/
  }

  /**
   * Generates the initialization vector to be used for encryption.
   * 
   * @return the initialization vector.
   */
  private byte[] getIV(final Context context) {
    // final SocialWorkerSharedPreferences sharedPreferences = SocialWorkerSharedPreferences.getInstance();
    // if (sharedPreferences.getIV() == null) {
      try {
        final SecureRandom random = new SecureRandom();
        final byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        // sharedPreferences.setIV(iv);
        return iv;
      } catch (final Exception e) {
        Log.e(TAG, "" + e.getMessage(), e);
        return null;
      }
    // } else {
    //   return sharedPreferences.getIV();
    // }
  }

  /**
   * Generates a random Base64 encoded string value.
   * 
   * @param length
   *          The length of the key.
   * @return A random key value.
   */
  public byte[] generateRandomKeyBytes(final int length) {
    byte[] randomKey = null;

    // Use a SecureRandom generator
    try {
      final SecureRandom secureRandom = new SecureRandom();
      final KeyGenerator keyGenerator = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
      keyGenerator.init(length, secureRandom);
      final SecretKey secretKey = keyGenerator.generateKey();
      randomKey = secretKey.getEncoded();
    } catch (final NoSuchAlgorithmException e) {
      Log.e(TAG, "Exception generating random key", e);
    }

    return randomKey;
  }

  /**
   * Generates a random Base64 encoded string value.
   * 
   * @param length
   *          The length of the key.
   * @return A random key value.
   */
  public String generateRandomKeyString(final int length) {
    return Base64.encodeToString(generateRandomKeyBytes(length), Base64.DEFAULT);
  }

  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
    try {
      if (ACTION_ENCRYPT_FILE.equals(action)) {
         JSONObject arg_object = args.getJSONObject(0);

         //TODO:Encrypt the file
         System.err.println("Action is encryption: " + action);
         System.err.println("URL: " + arg_object.getString("location"));
         encryptFile(arg_object.getString("location"),arg_object.getString("location"),null);
         callbackContext.success();
      }
      else if (ACTION_DECRYPT_FILE.equals(action)){
        //TODO:Decrypt the file
        JSONObject arg_object = args.getJSONObject(0);
        System.err.println("Action is decryption: " + action);
        System.err.println("URL: " + arg_object.getString("location"));
        decryptFile(arg_object.getString("location"),arg_object.getString("location"),null);
        callbackContext.success();
      } 
      callbackContext.error("Invalid action");
      return false;
    } catch(Exception e) {
        System.err.println("Exception: " + e.getMessage());
        callbackContext.error(e.getMessage());
        return false;
    } 
  }
}
