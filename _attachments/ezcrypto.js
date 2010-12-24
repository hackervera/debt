(function() {
  var ezcrypto = this.ezcrypto = {};
  
  ezcrypto.generateKeys = function() {
    var keys = RSAGenerate(ezcrypto.randomNumber());
    return {'public': keys.n, 'private': keys.d};
  }
  
  ezcrypto.encrypt = function(message, publicKey) {
    var bigNumSessionKey = new BigInteger(128, 1, ezcrypto.randomNumber());
    var sessionKey = bigNumSessionKey.toString(16);
    var encryptedMessage = byteArrayToHex(rijndaelEncrypt(message, hexToByteArray(sessionKey), 'ECB'));
    var encryptedKey = RSAEncrypt(sessionKey, publicKey);
    return {'key': encryptedKey, 'message': encryptedMessage};
  }
  
  ezcrypto.aes = function(message, key){
    var aes = new pidCrypt.AES.CBC();
    var encryptedMessage = aes.encryptText(message, key, {nBits: 128});
    return encryptedMessage;
  }
  
  ezcrypto.unaes = function(message, key){
    var aes = new pidCrypt.AES.CBC();
    //decrypt the crypted text and returns the plaintext
    //parameters; crypted text(base64 String), password(String) and options
    var plain = aes.decryptText(message, key, {nBits: 128});
    return plain;
  }
  
  ezcrypto.decrypt = function(encryptedMessage, encryptedKey, publicKey, privateKey) {
    var decryptedKey = RSADecrypt(encryptedKey, publicKey, privateKey);
    var decryptedMessage = byteArrayToString(rijndaelDecrypt(hexToByteArray(encryptedMessage), hexToByteArray(decryptedKey), 'ECB'));
    return decryptedMessage;
  }
  
  ezcrypto.randomNumber = function() {
    return new SecureRandom();
  }
  
  function load(scripts) {
    for (var i=0; i < scripts.length; i++) {
      document.write('<script src="'+scripts[i]+'"><\/script>')
    };
  };

  load([
    "vendor/pidcrypt.js",
    "vendor/pidcrypt_util.js",
    "vendor/asn1.js",
    "vendor/jsbn.js",
    "vendor/md5.js",
    "vendor/aes_core.js",
    "vendor/aes_cbc.js",
    "vendor/rng.js",
    "vendor/prng4.js",
    "vendor/rsa.js",
    "vendor/genkey.js",
    "vendor/rijndael.js",,
    "vendor/custom.js",
    "vendor/tohex.js"
  ]);
  
})();
