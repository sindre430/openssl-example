#include "crypto.hpp"
#include <iostream>

using namespace std;

int main() {
  cout << "SHA-1 with 1 iteration" << endl;
  cout << Crypto::hex(Crypto::sha1("Test")) << endl << endl;
  
  cout << "SHA-1 with two iterations" << endl;
  cout << Crypto::hex(Crypto::sha1(Crypto::sha1("Test"))) << endl;
  cout << Crypto::hex(Crypto::sha1("Test", 2)) << endl << endl;

  cout << "The derived key from the PBKDF2 algorithm" << endl;
  cout << Crypto::hex(Crypto::pbkdf2("Password", "Salt")) << endl << endl;

  cout << "MD5 with 1 iteration" << endl;
  cout << Crypto::hex(Crypto::md5("Test")) << endl << endl;
  
  cout << "SHA-256 with 1 iteration" << endl;
  cout << Crypto::hex(Crypto::sha256("Test")) << endl << endl;
   
   cout << "SHA-512 with 1 iteration" << endl;
   cout << Crypto::hex(Crypto::sha512("Test")) << endl << endl;
   
   
   cout << "Cracking PBKDF2 password" << endl;
   cout << Crypto::pbkdf2Crack("ab29d7b5c589e18b52261ecba1d3a7e7cbf212c6", "Saltet til Ola", 2048, 160/8) << endl << endl;
   
   cout << "Checking cracked password" << endl;
   cout << Crypto::hex(Crypto::pbkdf22("QwE", "Saltet til Ola", 2048, 160/8)) << endl << endl;
}
