#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "cryptor.h"

struct buffered_io
{
    buffered_io( BIO * bio )
        : m_bio( bio )
    {
    }

    ~buffered_io() noexcept
    {
        BIO_free( m_bio );
    }
protected:
    BIO * m_bio;
};

struct read_only_buffered_io : buffered_io
{
    read_only_buffered_io( char * buffer, int size )
        : buffered_io( BIO_new_mem_buf( buffer, size) )
    {
    }
};

struct rsa
{
    rsa()
        : m_rsa( RSA_new() )
    {
    }

    explicit
    rsa( RSA * rsaObject )
        : m_rsa( rsaObject )
    {
    };

    rsa( rsa && dead )
        : m_rsa( dead.m_rsa )
    {
        dead.m_rsa = nullptr;
    }

    ~rsa() noexcept
    {
        RSA_free( m_rsa );
    }

    operator RSA*() { return m_rsa; } 

    rsa& operator=( RSA * rsaObject )
    {
        m_rsa = rsaObject;
        return *this;
    }

    rsa& operator=( rsa && dead )
    {
        m_rsa = dead.m_rsa;
        dead.m_rsa = nullptr;
        return *this;
    }
private:
    RSA * m_rsa;
};

struct cryptor::envelope_key
{
    envelope_key()
        : m_key( EVP_PKEY_new() )
    {
        if (!m_key)
            throw std::bad_alloc();
    }

    bool set_private_key( std::string private_key, std::string password );
    bool set_public_key( std::string private_key, std::string password );

    ~envelope_key() noexcept
    {
        EVP_PKEY_free( m_key );
    }

private:
    rsa m_public_key, m_private_key;
    EVP_PKEY * m_key;
};

bool cryptor::envelope_key::set_private_key( std::string private_key, std::string password )
{
    // the buffer io is just an adapter for openssl to read into the std::string object
    read_only_buffered_io private_key_bio( 
        const_cast<char*>( private_key.c_str() ), private_key.size() );

    // load the rsa object (TODO: read in the private key)
    rsa temporary_rsa;
    RSA * const result = PEM_read_bio_RSAPrivateKey( private_key_bio, &temporary_rsa, nullptr, 0 );
    if ( result == nullptr )
        return false;

    // if everything went fine, move it to the data member
    m_private_key = std::move( rsa_private_key );

    return true;
}

bool cryptor::envelope_key::set_public_key( std::string public_key, std::string password )
{
    // the buffer io is just an adapter for openssl to read into the std::string object
    read_only_buffered_io public_key_bio( 
        const_cast<char*>(public_key.c_str()), public_key.size() );

    // load the rsa object (TODO: read in the public key)
    rsa temporary_rsa;
    RSA * const result = PEM_read_bio_RSAPublicKey( public_key_bio, &temporary_rsa, nullptr, 0 );
    if ( result == nullptr )
        return false;

    // if everything went fine, move it to the data member
    m_public_key = std::move( rsa_public_key );

    return true;
}

cryptor::cryptor( std::string private_key, std::string public_key )
    : cryptor( std::move( private_key ), "", std::move( public_key ), "" )
{
}

cryptor::cryptor( std::string private_key, std::string private_passwd,
                  std::string public_key,  std::string public_passwd )
    : m_key( new envelope_key )
{
    if ( !m_key->set_private_key( std::move( private_key ), std::move( private_passwd ) ) )
        throw invalid_key();

    if ( !m_key->set_public_key( std::move( public_key ), std::move( public_passwd ) ) )
        throw invalid_key();
}

cryptor::~cryptor() noexcept
{
    delete m_key;
}
