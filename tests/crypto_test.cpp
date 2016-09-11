#include "crypto.hpp"
#include <cassert>

using namespace std;

int main() {
  // Results copied from https://caligatio.github.io/jsSHA/
  assert(Crypto::hex(Crypto::sha1("Test")) == "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa");
  assert(Crypto::hex(Crypto::sha1("Test", 2)) == "af31c6cbdecd88726d0a9b3798c71ef41f1624d5");

  // Results copied from http://www.freecodeformat.com/pbkdf2.php
  assert(Crypto::hex(Crypto::pbkdf2("Password", "Salt", 4096, 128 / 8)) == "f66df50f8aaa11e4d9721e1312ff2e66");
  assert(Crypto::hex(Crypto::pbkdf2("Password", "Salt", 8192, 512 / 8)) == "a941ccbc34d1ee8ebbd1d34824a419c3dc4eac9cbc7c36ae6c7ca8725e2b618a6ad22241e787af937b0960cf85aa8ea3a258f243e05d3cc9b08af5dd93be046c");

  // Testing MD5 with 1 iteration. Result copied from http://www.xorbin.com/tools/md5-hash-calculator
  assert(Crypto::hex(Crypto::md5("Test")) == "0cbc6611f5540bd0809a388dc95a615b");
  
  // Testing SHA-256 with 1 iteration. Result copied from http://www.xorbin.com/tools/sha256-hash-calculator
  assert(Crypto::hex(Crypto::sha256("Test")) == "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25");
  
  // Testing SHA-512 with 1 iteration. Result copied from http://abunchofutils.com/u/computing/sha512-hash-calculator/
  assert(Crypto::hex(Crypto::sha512("Test")) == "c6ee9e33cf5c6715a1d148fd73f7318884b41adcb916021e2bc0e800a5c5dd97f5142178f6ae88c8fdd98e1afb0ce4c8d2c54b5f37b30b7da1997bb33b0b8a31");
  
  // Testing password for Ola (pbkdf2 algorithm with key:"ab29d7b5c589e18b52261ecba1d3a7e7cbf212c6", salt:"Saltet til Ola", iterations: 2048, key length: 160/8)
  assert(Crypto::hex(Crypto::pbkdf22("QwE", "Saltet til Ola", 2048, 160/8)) == "ab29d7b5c589e18b52261ecba1d3a7e7cbf212c6");
}
