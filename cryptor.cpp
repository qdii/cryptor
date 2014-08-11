#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <assert.h>
#include <memory>
#include <list>
#include <algorithm>
#include <string.h>
#ifndef NDEBUG
#   include <iostream>
#endif

#include "cryptor.h"

static inline
void check_errors()
{
#ifndef NDEBUG
    const int error = ERR_get_error();
    if ( error != 0 )
    {
        std::cerr << ERR_reason_error_string( error ) << '\n';
        assert( 0 );
    }
#endif
}

struct buffered_io
{
    buffered_io( BIO * bio )
        : m_bio( bio )
    {
    }

    ~buffered_io() noexcept
    {
        BIO_free( m_bio );
        check_errors();
    }

    operator const BIO * () const
    {
        return m_bio;
    }

    operator BIO * () const
    {
        return m_bio;
    }

protected:
    BIO * m_bio;
};

static
int feed_password( char * buffer_expecting_passwd,
                   int max_password_size, int rwflag,
                   void * password_string_ptr )
{
    assert( rwflag == 0 );
    std::string * const password =
        reinterpret_cast< std::string * >( password_string_ptr );
    assert( password != nullptr );

    if ( password->size() > max_password_size )
        throw password_is_too_long();

    const int nb_chars_copied =
        password->copy( buffer_expecting_passwd, max_password_size );

    return nb_chars_copied;
}

struct read_only_buffered_io : buffered_io
{
    read_only_buffered_io( char * buffer, int size )
        : buffered_io( BIO_new_mem_buf( buffer, size ) )
    {
        check_errors();
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

    rsa( std::string data, bool is_private_key, std::string password )
        : rsa()
    {
        // the buffer io is just an adapter for openssl to read into the std::string object
        read_only_buffered_io buffer(
            const_cast<char *>( data.c_str() ), data.size() );

        rsa temporary_rsa;
        RSA * const result =
            is_private_key ? PEM_read_bio_RSAPrivateKey( buffer, &temporary_rsa,
                    feed_password, &password )
            : PEM_read_bio_RSAPublicKey ( buffer, &temporary_rsa, feed_password,
                                          &password );
        check_errors();
        if ( result == nullptr )
            throw invalid_key();

        // if everything went fine, move it to the data member
        m_rsa = temporary_rsa.m_rsa;
        temporary_rsa.m_rsa = nullptr;
    }

    rsa( rsa && dead )
        : m_rsa( dead.m_rsa )
    {
        dead.m_rsa = nullptr;
    }

    ~rsa() noexcept
    {
        RSA_free( m_rsa );
        check_errors();
    }

    operator RSA * ()
    {
        return m_rsa;
    }
    RSA ** operator&()
    {
        return &m_rsa;
    }

    rsa & operator=( RSA * rsaObject )
    {
        m_rsa = rsaObject;
        return *this;
    }

    rsa & operator=( rsa && dead )
    {
        m_rsa = dead.m_rsa;
        dead.m_rsa = nullptr;
        return *this;
    }
private:
    RSA * m_rsa;
};

struct rsa_key_pair
{
    void set_private_key( std::string private_key, std::string password );
    void set_public_key( std::string private_key, std::string password );

    std::shared_ptr<rsa> public_key() const
    {
        return m_public_key;
    }

    std::shared_ptr<rsa> private_key() const
    {
        return m_private_key;
    }

private:
    std::shared_ptr<rsa> m_public_key, m_private_key;
};

void rsa_key_pair::set_private_key( std::string private_key,
                                    std::string password )
{
    m_private_key.reset( new rsa( private_key, true, password ) );
}

void rsa_key_pair::set_public_key( std::string public_key,
                                   std::string password )
{
    m_public_key.reset( new rsa( public_key, false, password ) );
}

cryptor::cryptor( std::string private_key, std::string public_key )
    : cryptor( std::move( private_key ), "", std::move( public_key ), "" )
{
}

cryptor::cryptor( std::string private_key, std::string private_passwd,
                  std::string public_key,  std::string public_passwd )
    : m_keys( new rsa_key_pair )
{
    // load error messages
    ERR_load_crypto_strings();

    m_keys->set_private_key( std::move( private_key ),
                             std::move( private_passwd ) );

    m_keys->set_public_key( std::move( public_key ),
                            std::move( public_passwd ) );
}

/**@brief Splits a string into fixed-size chunks */
static
std::list< std::string >
split_string( std::string origin, const size_t chunk_size )
{
    std::list< std::string > chunks;
    size_t i = 0;
    const size_t total = origin.size();

    while ( i < total )
    {
        std::string new_chunk = origin.substr( i, chunk_size );
        chunks.push_back( origin.substr( i, chunk_size ) );
        i += chunk_size;
        assert( chunks.back().size() <= chunk_size );
    }

    return chunks;
}

struct string_appender
{
    string_appender( std::string & original_string )
        : m_original_string( original_string )
    {
    }

    string_appender & operator=( std::string string_to_append )
    {
        m_original_string.append( string_to_append );
        return *this;
    }

    string_appender & operator++()
    {
        return *this;
    }
    string_appender & operator* ()
    {
        return *this;
    }
    string_appender & operator++( int )
    {
        return *this;
    }

private:
    std::string & m_original_string;
};

/**@brief A structure which operator() encrypts a short block of data */
struct block_encrypter
{
    /**@brief Constructs a block encrypter
     * @param[in] public_key The key used to encrypt the data */
    explicit
    block_encrypter( std::shared_ptr<rsa> public_key )
        : m_public_key( public_key )
        , m_buffer_size( RSA_size( *public_key ) )
        , m_buffer( new unsigned char[ m_buffer_size ] )
    {
        check_errors();
        memset( m_buffer.get(), 0, m_buffer_size );
    }

    /**@brief Encrypts a block of data
     * @param[in] clear_text The text to encrypt */
    std::string operator()( const std::string & clear_text )
    {
        const int nb_bytes_encrypted =
            RSA_public_encrypt(
                clear_text.size(),
                reinterpret_cast< const unsigned char * >(
                    clear_text.data() ),
                m_buffer.get(),
                *m_public_key,
                RSA_PKCS1_OAEP_PADDING
            );

        check_errors();
        if ( nb_bytes_encrypted == -1 )
            throw cannot_encrypt( ERR_reason_error_string( ERR_get_error() ) );

        return std::string( reinterpret_cast<char *>( m_buffer.get() ),
                            nb_bytes_encrypted );
    }

private:
    std::shared_ptr<rsa> m_public_key;
    const size_t m_buffer_size;
    std::unique_ptr< unsigned char[] > m_buffer;
};

std::string cryptor::encrypt( std::string clear_text )
{
    assert( m_keys );
    assert( m_keys->public_key() != nullptr );
    std::string encrypted_data;

    // split the text into blocks
    const auto blocks_to_encrypt =
        split_string( clear_text, RSA_size( *m_keys->public_key() ) - 42 );
    check_errors();

    std::transform( blocks_to_encrypt.cbegin(), blocks_to_encrypt.cend(),
                    string_appender( encrypted_data ),
                    block_encrypter( m_keys->public_key() ) );


    return encrypted_data;
}

/**@brief A structure which operator() decrypts a short block of data */
struct block_decrypter
{
    /**@brief Constructs a block decrypter
     * @param[in] private_key The key used to decrypt the data */
    explicit
    block_decrypter( std::shared_ptr<rsa> private_key )
        : m_private_key( private_key )
        , m_buffer_size( RSA_size( *private_key ) )
        , m_buffer( new unsigned char[ m_buffer_size ] )
    {
        check_errors();
        memset( m_buffer.get(), 0, m_buffer_size );
    }

    /**@brief Decrypts a block of data
     * @param[in] crypted_data The text to decrypt */
    std::string operator()( const std::string & crypted_data )
    {
        const int nb_bytes_decrypted =
            RSA_private_decrypt(
                crypted_data.size(),
                reinterpret_cast< const unsigned char * >(
                    crypted_data.data() ),
                m_buffer.get(),
                *m_private_key,
                RSA_PKCS1_OAEP_PADDING
            );
        check_errors();
        if ( nb_bytes_decrypted == -1 )
            throw cannot_decrypt( ERR_reason_error_string( ERR_get_error() ) );

        assert( nb_bytes_decrypted <= m_buffer_size );
        return std::string( reinterpret_cast<char *>( m_buffer.get() ),
                            nb_bytes_decrypted );
    }

private:
    std::shared_ptr<rsa> m_private_key;
    const size_t m_buffer_size;
    std::unique_ptr< unsigned char[] > m_buffer;
};

std::string cryptor::decrypt( std::string crypted_data )
{
    assert( m_keys );
    assert( m_keys->private_key() != nullptr );

    std::string decrypted_data;
    const std::list< std::string > chunks =
        split_string( crypted_data, RSA_size( *m_keys->private_key() ) );

    // split the crypted text into chunks, decrypt each chunk, and append
    // them one by one to decrypted_data
    std::transform( chunks.cbegin(), chunks.cend(),
                    string_appender( decrypted_data ),
                    block_decrypter( m_keys->private_key() ) );

    return decrypted_data;
}

cryptor::~cryptor() noexcept
{
}

