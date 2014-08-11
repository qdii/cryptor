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

static
bool test_binary_decryption()
{
    cryptor c( private_key_without_password, public_key_without_password );

    const std::string clear_text( "abc\0def\n\t\rghi" );
    const std::string encrypted_text = c.encrypt( clear_text );
    const std::string decrypted_text = c.decrypt( encrypted_text );

    if ( clear_text != decrypted_text )
        return false;

    return true;


}

static const char * private_key_with_password =
    R"(-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANlAx1BAaX1oD9lu
VGbLRVVviQ67L+QPta/NMtaIdtpR0+MrdhRMTm7MwVT3B86GXtehMO129kowD9ZT
cUEsuasgTnTLQCkV+Tx7YKE4EHtChy3dUvK3uAn442qWVWgTY4vXJjAFvdcYD6nY
aztswqQetyt5Irckcfv1WPt2mz5pAgMBAAECgYEA1vgSQIZ722ssw6k4Or7ITFGg
/MKcEL66uMoCk+VUNZLiZtaKcGtQ8LIKW1hUkTbEgfktwMsFyULlaN4IIsVusOGK
09q/zlu63qkZA5Sep5z8NVuNh0xdJ+MsCUH9AmcHT1ISy2al/siJ8MyZmmyPEAOJ
3p+qp5+Pi1drALiFiUECQQD/OyAvEh4THADh8d4HQ83pioUoJpF50avM/3BvO+uk
vHdcPXlYJpEQkR09ziiEphv/E7C3pwxMBKu25odfrOKjAkEA2ehbubnJdyyWebHK
pzizbbB5nt2KgutndIM5s92G5sAhdGUXeEaXxKIi6AKs7+f+WsiMNt3bcM+tsqRi
Iyj3gwJBAMfoBH45v4qSHXLbIV8pUWeBUmgvRTRX8CshS2wkT53467g4ggl0M5z5
PCEDjyLOhBEW2AwQcAY+hkw8ZX2fiOcCQE77I1P7/QPPC3Nsd7GIobBeSJbGYc/2
FvdqIN4Kqzyz4uxXP9x+acABrHk/jwMdqVmqWvgADeujuqeHYXKxBJUCQQDV4Lm8
goSY2UEtFHuD+GYArwh4C3rNqgVjgjVEtISU3yF4JUkCzpBsOKeh9gJkVwhsn6n+
u6Y0tU60TxQ9egO6
-----END PRIVATE KEY-----)";

static const char * public_key_with_password =
    R"(-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBANlAx1BAaX1oD9luVGbLRVVviQ67L+QPta/NMtaIdtpR0+MrdhRMTm7M
wVT3B86GXtehMO129kowD9ZTcUEsuasgTnTLQCkV+Tx7YKE4EHtChy3dUvK3uAn4
42qWVWgTY4vXJjAFvdcYD6nYaztswqQetyt5Irckcfv1WPt2mz5pAgMBAAE=
-----END RSA PUBLIC KEY-----)";

static
bool test_simple_encryption_with_password()
{
    cryptor c( private_key_with_password, "123456",
               public_key_with_password, "" );

    const std::string clear_text = "Hello, world\n";
    const std::string encrypted_text = c.encrypt( clear_text );

    if ( encrypted_text.empty() )
        return false;

    return true;

}

static
bool test_simple_decryption_with_password()
{
    cryptor c( private_key_with_password, "123456", public_key_with_password, "" );

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

struct encrypting_ostream : public std::ostream
{
    explicit
    encrypting_ostream( std::string encrypting_key, std::ostream & ostr,
                        std::string password = "" )
        : std::ostream( &m_encrypting_buffer )
        , m_encrypting_buffer( std::move( encrypting_key ), ostr,
                               std::move( password ) )
    {
    }

    virtual ~encrypting_ostream() noexcept
    {
    }

private:
    cryptbuf m_encrypting_buffer;
};

static
bool test_encrypt_stream()
{
    std::stringstream stream_which_receives_encrypted_contents;

    // create a stream that automatically encrypts the contents and flushes into another stream
    encrypting_ostream ostr( public_key_without_password,
                             stream_which_receives_encrypted_contents );

    // pushes some text into it
    ostr << "Hello, " << "world" << std::endl;

    // checks that the initial stream has received correctly encoded data
    cryptor c( private_key_without_password, "", public_key_without_password, "" );
    const std::string encrypted_contents =
        stream_which_receives_encrypted_contents.str();
    const std::string decrypted_contents = c.decrypt( encrypted_contents );

    if ( decrypted_contents != "Hello, world\n" )
        return false;

    return true;
}

static
bool test_encrypt_binary_stream()
{
    std::stringstream stream_which_receives_encrypted_contents;

    // create a stream that automatically encrypts the contents and flushes into another stream
    encrypting_ostream ostr( public_key_without_password,
                             stream_which_receives_encrypted_contents );

    // pushes some text into it
    ostr.write( "Hell\0o, ", 8 );
    ostr.write( "world", 5 );
    ostr.flush();

    // checks that the initial stream has received correctly encoded data
    cryptor c( private_key_without_password, "", public_key_without_password, "" );
    const std::string encrypted_contents =
        stream_which_receives_encrypted_contents.str();
    const std::string decrypted_contents = c.decrypt( encrypted_contents );
    const std::string original_string( "Hell\0o, world", 13 );

    if ( decrypted_contents != original_string )
        return false;

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
    LAUNCH( test_binary_decryption );
    LAUNCH( test_simple_encryption_with_password );
    LAUNCH( test_simple_decryption_with_password );
    LAUNCH( test_encrypt_stream );
    LAUNCH( test_encrypt_binary_stream );
}
