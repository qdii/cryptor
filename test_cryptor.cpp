#include <utility>
#include <functional>
#include <string>
#include <iostream>
#include <assert.h>

#include "cryptor.h"

static const char * private_key_without_password =
    R"(-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDG+3UbG3/9qkp1bEY2yj0JLE0T7yOggJ4dChZ0/Kfi+6zlMdZn
1HIWrNAOMRbGUHP7+GyPAjr+GV7QHm5RG2kF7REp1EihSYhBk6B5CqOdP1z1PTTV
2Aasa9Fsu2thN79Vjqh09vf0Cy6+LCo7j7QbwADuCWjzMkIA4t1x4zhI5wIDAQAB
AoGBAJv5iHZTPCTvU6Zv1SolpWqHW3QAxICP0WEaAzh4xHFcrs6KHnMNSNEVbZFy
UVPqxMACn7YKHYwI/xVMhVT2k387kIrDpJov7F9Z4PV5/5gicyU00nIbDlNoqRW8
Lb1JM/LV+gHGF4ttjRgCXgNw0ranAbq21Qx0bH1EDszelEQhAkEA6wq/XxHJ9tfj
Nk2JXdAUgt+OJDfDi2qKvmo2fvNJpWHLsw/8FOdOcWlk1onDnzPavZnHBLpOk9Rz
HynKSVuewwJBANi5lRLjQLTTku/KVp1QJRSyd1fb7Z1vqyka6otOkHNxbnXQNMqT
zHbx/b6vDOy+Kyd5+wX1h0o++1VpdZUIUw0CQA0VTBG+q79RxRQAvOS78GhYiVD6
yae5BoAS6XWnlTHff7c37JA9T+CAPVyzzm/OMx7asHlS5YzVBpN1gA0VTIECQG0H
X/Gylfjif4dW2aAmk6EH73Yp1C5h4U+6lMgkbBNHu3RVnFlVZYVpVGg7lFr9iKRB
f4GN9dPqP3LGrTqeh3kCQQCEfhnp5ldj+ldETL9NY0tReyN7eTz7l0OXf4Z47TCc
8PIAiS8s2q7t6klVRwN7yVpyAZjxILcyrAGD/OXpSjCb
-----END RSA PRIVATE KEY-----)";

static const char * public_key_without_password =
    R"(-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMb7dRsbf/2qSnVsRjbKPQksTRPvI6CAnh0KFnT8p+L7rOUx1mfUchas
0A4xFsZQc/v4bI8COv4ZXtAeblEbaQXtESnUSKFJiEGToHkKo50/XPU9NNXYBqxr
0Wy7a2E3v1WOqHT29/QLLr4sKjuPtBvAAO4JaPMyQgDi3XHjOEjnAgMBAAE=
-----END RSA PUBLIC KEY-----)";

#define LAUNCH( X ) launch( X, #X )

static
bool launch( std::function< bool() > fnc, std::string name )
{
    std::cout << name << ": ";
    try
    {
        const bool success = fnc();
        std::cout << ( success ? "OK\n" : "FAILED\n" );
        return success;
    }
    catch( const std::exception & exc )
    {
        std::cout << "FAILED (exception: " << exc.what() << ")\n";
        return false;
    }
    catch( ... )
    {
        std::cout << "FAILED(exception)\n";
        return false;
    }

    assert( 0 );
    return true;
}

static
bool test_simple_encryption()
{
    cryptor c( private_key_without_password, public_key_without_password );

    const std::string clear_text = "Hello, world\n";
    const std::string encrypted_text = c.encrypt( clear_text );

    if ( encrypted_text.empty() )
        return false;

    return true;
}

static
bool test_short_encryption()
{
    cryptor c( private_key_without_password, public_key_without_password );

    const std::string clear_text = "g";
    const std::string encrypted_text = c.encrypt( clear_text );

    if ( encrypted_text.empty() )
        return false;

    return true;
}

static
bool test_empty_encryption()
{
    cryptor c( private_key_without_password, public_key_without_password );

    const std::string clear_text = "";
    const std::string encrypted_text = c.encrypt( clear_text );

    return true;
}

static
bool test_long_encryption()
{
    cryptor c( private_key_without_password, public_key_without_password );

    const std::string clear_text =
        R"(Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum)";
    const std::string encrypted_text = c.encrypt( clear_text );

    if ( encrypted_text.empty() )
        return false;

    if ( encrypted_text.size() < clear_text.size() )
        return false;

    return true;
}

static
bool test_long_decryption()
{
    cryptor c( private_key_without_password, public_key_without_password );

    const std::string clear_text =
        R"(Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum)";
    const std::string encrypted_text = c.encrypt( clear_text );

    if ( encrypted_text.empty() )
        return false;

    if ( encrypted_text.size() < clear_text.size() )
        return false;

    const std::string decrypted_text = c.decrypt( encrypted_text );
    if ( decrypted_text != clear_text )
        return false;

    return true;
}

static
bool test_simple_decryption()
{
    cryptor c( private_key_without_password, public_key_without_password );

    const std::string clear_text = "Hello, world\n";
    const std::string encrypted_text = c.encrypt( clear_text );

    if ( encrypted_text.empty() )
        return false;

    const std::string decrypted_text = c.decrypt( encrypted_text );
    if ( decrypted_text.empty() )
        return false;

    if ( clear_text != decrypted_text )
        return false;

    return true;
}

static
bool test_simple_constructor()
{
    cryptor c( private_key_without_password, public_key_without_password );
    return true;
}

int main()
{
    LAUNCH( test_simple_constructor );
    LAUNCH( test_simple_encryption );
    LAUNCH( test_short_encryption );
    LAUNCH( test_empty_encryption );
    LAUNCH( test_long_encryption );
    LAUNCH( test_simple_decryption );
    LAUNCH( test_long_decryption );
}
