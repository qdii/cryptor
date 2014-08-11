This is a simple class that can encrypt and decrypt strings using RSA.
Simple code that shows how to use std::clog to encrypt logs:

```
#include <iostream>
#include <fstream>

#include "cryptor.h"

static const char * rsa_key =
    R"(-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMb7dRsbf/2qSnVsRjbKPQksTRPvI6CAnh0KFnT8p+L7rOUx1mfUchas
0A4xFsZQc/v4bI8COv4ZXtAeblEbaQXtESnUSKFJiEGToHkKo50/XPU9NNXYBqxr
0Wy7a2E3v1WOqHT29/QLLr4sKjuPtBvAAO4JaPMyQgDi3XHjOEjnAgMBAAE=
-----END RSA PUBLIC KEY-----)";

int main()
{
    std::ofstream log_file( "log.dat", std::ios_base::binary );

    // std::clog will now encrypt all data
    cryptbuf cryptengine( rsa_key, log_file );
    std::clog.rdbuf( &cryptengine );

    // enjoy
    std::clog << "Engine started" << std::endl;

    // release
    std::clog.rdbuf( nullptr );
}
```

