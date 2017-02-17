package com.rmd;

import javax.crypto.SecretKey;

/**
 * Created by randy on 2/17/2017.
 */
public class AESMessageDTO {

    private String _plainText = "";
    public String get_plainText() {
        return _plainText;
    }
    public void set_plainText(String _plainText) {
        this._plainText = _plainText;
    }

    private String _cipherText = "";
    public String get_cipherText() {
        return _cipherText;
    }
    public void set_cipherText(String _cipherText) {
        this._cipherText = _cipherText;
    }

    private String _key = "";
    public String get_key() {
        return _key;
    }
    public void set_key(String _key) {
        this._key = _key;
    }
//    public SecretKey get_secret_key() { SecretKey k;
//    k.
//    };

    private String _iv = "";
    public String get_iv() {
        return _iv;
    }
    public void set_iv(String _iv) {
        this._iv = _iv;
    }
}
