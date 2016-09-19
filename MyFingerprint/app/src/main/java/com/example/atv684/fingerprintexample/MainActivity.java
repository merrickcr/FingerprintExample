package com.example.atv684.fingerprintexample;

import android.Manifest;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;
import android.os.Handler;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import org.w3c.dom.Text;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class MainActivity extends AppCompatActivity {

    Cipher cipher;

    KeyStore keyStore;

    KeyGenerator keyGenerator;

    CancellationSignal cancellationSignal;

    String FINGERPRINT_KEY_ALIAS = "FINGERPRINT_KEY";

    String cipherResult = "DATA TO ENCRYPT/DECRYPT";

    byte[] ivSpec;

    private boolean shouldEncrypt = true;

    TextView textView;

    TextView errorTextView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        textView = (TextView) findViewById(R.id.textview);

        errorTextView = (TextView) findViewById(R.id.error_textview);

        cipherResult = textView.getText().toString();

    }


    @Override
    protected void onPause() {
        super.onPause();

        if(cancellationSignal.isCanceled() == false) {
            cancellationSignal.cancel();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();

        loadKeystore();

        try {
            if (!keyStore.containsAlias(FINGERPRINT_KEY_ALIAS)) {
                generateKey();
            }
        }
        catch(KeyStoreException e){
            Log.e("ON RESUME", e.getMessage());
        }

        startListening();
    }

    private void loadKeystore() {
        try{
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
        }
        catch(KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e){
            Log.e("MAIN ACTIVITY", e.getMessage());
        }
    }

    public void startListening() {

        FingerprintManager fingerprintManager =
                (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);

        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT)
                != PackageManager.PERMISSION_GRANTED) {
            return;
        }

        if(fingerprintManager.hasEnrolledFingerprints()
                && fingerprintManager.isHardwareDetected()){
            //Good to go! start listening

            Cipher cipher = getCipher();

            FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);

            cancellationSignal = new CancellationSignal();

            fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, callBack, null);
        }
    }

    protected void generateKey() {

        try {
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(
                    "Failed to get KeyGenerator instance", e);
        }

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(FINGERPRINT_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);

        KeyGenParameterSpec spec = builder.setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setUserAuthenticationRequired(true)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build();

        try {
            keyGenerator.init(spec);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        keyGenerator.generateKey();

    }


    public Cipher getCipher() {
        try {
            cipher = Cipher.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES + "/"
                            + KeyProperties.BLOCK_MODE_CBC + "/"
                            + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException |
                NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }

        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(FINGERPRINT_KEY_ALIAS, null);

            if(shouldEncrypt == false){
                cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivSpec));
            }
            else {
                cipher.init(Cipher.ENCRYPT_MODE, key);
            }

            return cipher;
        } catch (KeyPermanentlyInvalidatedException | InvalidAlgorithmParameterException e) {
            return null;
        } catch (KeyStoreException | CertificateException
                | UnrecoverableKeyException | IOException
                | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }

    }


    FingerprintManager.AuthenticationCallback callBack = new FingerprintManager.AuthenticationCallback() {
        @Override
        public void onAuthenticationError(int errorCode, CharSequence errString) {
            super.onAuthenticationError(errorCode, errString);

            errorTextView.setText(errString);
        }

        @Override
        public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
            super.onAuthenticationHelp(helpCode, helpString);

            errorTextView.setText(helpString);
        }

        @Override
        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
            super.onAuthenticationSucceeded(result);

            Cipher cipher = result.getCryptoObject().getCipher();

            errorTextView.setText("");

            try {

                //toggle between encryption/decryption and set IV on encryption
                if(shouldEncrypt){
                    byte[] data = cipher.doFinal(cipherResult.getBytes());
                    ivSpec = cipher.getIV();
                    cipherResult = Base64.encodeToString(data, Base64.NO_WRAP);
                    shouldEncrypt = false;
                }
                else{
                    byte[] data = cipher.doFinal(Base64.decode(cipherResult.getBytes(), Base64.NO_WRAP));
                    cipherResult = new String(data, "UTF-8");
                    shouldEncrypt = true;
                }

                Log.e("TAG", cipherResult);

                textView.setText(cipherResult);

                //add a delay so we don't spam the scanner
                new Handler().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        startListening();
                    }
                }, 200);

                //or enable listening immediately
                //startListening();
            } catch (IllegalBlockSizeException | UnsupportedEncodingException |
                    BadPaddingException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void onAuthenticationFailed() {
            super.onAuthenticationFailed();

            errorTextView.setText("Fingerprint not authorized!");
        }

    };

}
