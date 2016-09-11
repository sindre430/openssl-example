#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <sstream>
#include <iomanip>
#include <string>
#include <math.h>

#include <iostream>

// Note: C-style casts, for instance (int), are used to simplify the source code.
//       C++ casts, such as static_cast and reinterpret_cast, should otherwise
//       be used in modern C++.

/// Limited C++ bindings for the OpenSSL Crypto functions.
class Crypto {
public:
  /// Return hex string from bytes in input string.
  static std::string hex(const std::string &input) {
    std::stringstream hex_stream;
    hex_stream << std::hex << std::internal << std::setfill('0');
    for (auto &byte : input)
      hex_stream << std::setw(2) << (int)(unsigned char)byte;
    return hex_stream.str();
  }

  /// Return the MD5 (128-bit) hash from input.
  static std::string md5(const std::string &input, size_t iterations = 1) {
    std::string hash;
    hash.resize(128/8);
    MD5((const unsigned char *)input.c_str(), input.size(), (unsigned char *)hash.c_str());
    
    return hash;
  }

  /// Return the SHA-1 (160-bit) hash from input.
  static std::string sha1(const std::string &input, size_t iterations = 1) {
    std::string hash;
    hash.resize(160 / 8);
    SHA1((const unsigned char *)input.c_str(), input.size(), (unsigned char *)hash.c_str());

    for (size_t c = 1; c < iterations; ++c)
      SHA1((const unsigned char *)hash.c_str(), hash.size(), (unsigned char *)hash.c_str());

    return hash;
  }

  /// Return the SHA-256 (256-bit) hash from input.
  static std::string sha256(const std::string &input, size_t iterations = 1) {
    std::string hash;
    hash.resize(256/8);
    SHA256((const unsigned char *)input.c_str(), input.size(), (unsigned char *)hash.c_str());
    
    return hash;
  }

  /// Return the SHA-512 (512-bit) hash from input.
  static std::string sha512(const std::string &input, size_t iterations = 1) {
    std::string hash;
    hash.resize(512/8);
    SHA512((const unsigned char *)input.c_str(), input.size(), (unsigned char *)hash.c_str());
    
    return hash;
  }

  /// Return key from the Password-Based Key Derivation Function 2 (PBKDF2).
  static std::string pbkdf2(const std::string &password, const std::string &salt, int iterations = 4096, int key_length = 256 / 8) {
    std::string key;
    key.resize(key_length);
    auto success = PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(),
                                          (const unsigned char *)salt.c_str(), salt.size(), iterations,
                                          key_length, (unsigned char *)key.c_str());
    if (!success)
      throw std::runtime_error("openssl: error calling PBKCS5_PBKDF2_HMAC_SHA1");
    return key;
  }
  
  /// Return key from the Password-Based Key Derivation Function 2 (PBKDF2).
   static std::string pbkdf22(const std::string &password, const std::string &salt, int iterations , int key_length) {
     std::string key;
     key.resize(key_length);
     auto success = PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(),
                                           (const unsigned char *)salt.c_str(), salt.size(), iterations,
                                           key_length, (unsigned char *)key.c_str());
     if (!success)
       throw std::runtime_error("openssl: error calling PBKCS5_PBKDF2_HMAC_SHA1");
     return key;
   }
  
  /// Returns string with the password matching pdkdf2 hash with given hash and salt
 /* static std::string pbkdf2Crack(const std::string &key, const std::string &salt, int iterations){
    const char posChars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
   // const char posChars[] = "EFGHIJKLMNOPQWw";
    int length = 62;
    //int length = 15;
    int tries = 0;
    bool found = false;
    std::string curString = "";
    
    while(!found){
      curString  ="";
      int charCount = floor(tries/length);
      if(charCount < pow(length, 0)) charCount = 1; //1 bok
      else if (charCount <= pow(length, 1)) charCount = 2; //2 bok
      else if (charCount <= pow(length, 2)) charCount = 3; //3 bok 
      else if (charCount <= pow(length, 3)){//4 bok 
        found = true;
        break;
      }
      
      if(charCount > 1){
        int c1 = tries/pow(length, (charCount-1))-1;
        int c2 = 
        
      }
      
      if(charCount == 1){
        curString = std::string(1, posChars[tries]);
      }
      else if(charCount == 2){
        std::string c1 = std::string(1, posChars[(tries/length)-1]);
        std::string c2 = std::string(1, posChars[tries%length]);
         curString = c1+c2;
      }
      if (charCount == 3){
        int mid = (floor((tries-length*length)/length)-1);
        std::string c1 = std::string(1, posChars[(tries/(length*length)-1)]);
        std::string c2 = std::string(1, posChars[mid%length]);
        std::string c3 = std::string(1, posChars[tries%length]);
        
        curString = c1+c2+c3;

      }
      
      std::string cKey;
      cKey.resize(128/8);
      auto success = PKCS5_PBKDF2_HMAC_SHA1(curString.c_str(), curString.size(),
                                            (const unsigned char *)salt.c_str(), salt.size(), iterations,
                                            128/8, (unsigned char *)cKey.c_str());
      if (!success) throw std::runtime_error("openssl: error calling PBKCS5_PBKDF2_HMAC_SHA1");
      
      
      if((cKey == key) == 1){
        std::cout << curString;
        found = true;
      }
      
      tries++;
    }
   
    
    return curString;
  }*/
  
  static std::string pbkdf2Crack(const std::string key, const std::string salt, int iterations, int key_length){
    const int lowDec = 48; 
    const int highDec = 122; 
    int numberOfChar = 1;
    bool found = false;
    std::string password = "";
    
    while(!found){
      char curPass[numberOfChar];
      
      if(numberOfChar == 1){
        for(int i=lowDec; i<=highDec; i++){
          password = "";
          password += (char)i;
          
          if(Crypto::hex(Crypto::pbkdf22(password, salt, iterations, key_length)) == key){
            return password;
          }
          numberOfChar = 2;
        }
      }
        
        if(numberOfChar == 2){
          for(int i=lowDec; i<=highDec; i++){
            for(int j=lowDec; j<=highDec; j++){
              password = "";
              
              curPass[0] = (char)i;
              curPass[1] = (char)j;
              
              for(int o=0; o<numberOfChar; o++){
                password+=curPass[o];
              }
              
              if(Crypto::hex(Crypto::pbkdf22(curPass, salt, iterations, key_length)) == key){
                return password;
              }
            }
          }
          numberOfChar = 3;
        }
        
        if(numberOfChar == 3){
          for(int i=lowDec; i<=highDec; i++){
            for(int j=lowDec; j<=highDec; j++){
              for(int k=lowDec; k<=highDec; k++){
                password = "";
                
                curPass[0] = (char)i;
                curPass[1] = (char)j;
                curPass[2] = (char)k;
                
                for(int o=0; o<numberOfChar; o++){
                  password+=curPass[o];
                }
                
            
                if(Crypto::hex(Crypto::pbkdf22(password, salt, iterations, key_length)) == key){
                  return password;
                }
              }
            }
          }
          found = true;
          std::cout << "ikke funnet";
          password = "Not Found";
        }
        
    }
    return password;
    
  }
};
