# cpp-bcrypt
A cpp port of the javascript bcrypt library.

## Usage

```cpp
#include <iostream>
#include <bcrypt.hpp>

int main(){
  std::string hash = bcrypt::hash("this is the string", 10); // hash 16 times
  std::cout << hash << "\n"; // $2a$10$T52Pgdtc43ikySun8/X7L.KzygvwjoCPraRag/kmd2ifP8qMuCvwW

  return EXIT_SUCCESS;
}

```
