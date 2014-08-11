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

/**@brief Hands a password to openssl
 * @param[in] buffer expecting_passwd A buffer which openssl
 *                   will read the password from
 * @param[in] max_password_size openssl tells us that a password
 *                              has to be shorter than this
 * @param[in] rwflag 0 when openssl reads a password from the buffer,
 *                   1 when it writes to it
 * @param[in] password_string_ptr user data I use to store the password */
static
int feed_password( char * buffer_expecting_passwd,
                   int max_password_size, int rwflag,
                   void * password_string_ptr )
{
    assert( rwflag == 0 );
    std::string * const password =
        reinterpret_cast< std::string * >( password_string_ptr );
    assert( password != nullptr );

    if ( password->size() > static_cast< size_t >( max_password_size ) )
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

    if ( !private_key.empty() )
        m_keys->set_private_key( std::move( private_key ),
                                 std::move( private_passwd ) );

    if ( !public_key.empty() )
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

/**@brief A structure which operator() decrypts / encrypts a short block of data */
struct block_crypter
{
    /**@brief Constructs a block decrypter
     * @param[in] key The key used to decrypt or encrypt the data
     * @param[in] perform_encryption True to perform encryption, false to perform decryption */
    block_crypter( std::shared_ptr<rsa> key, const bool perform_encryption )
        : m_key( key )
        , m_buffer_size( RSA_size( *m_key ) )
        , m_buffer( new unsigned char[ m_buffer_size ] )
        , m_cipher_function( perform_encryption ? RSA_public_encrypt :
                             RSA_private_decrypt )
    {
        check_errors();
        memset( m_buffer.get(), 0, m_buffer_size );
    }

    block_crypter( rsa_key_pair & key_pair, const bool perform_encryption )
        : block_crypter( perform_encryption ? key_pair.public_key() :
                         key_pair.private_key(),
                         perform_encryption )
    {
    }

    /**@brief Decrypts or encrypts a block of data
     * @param[in] input The text to treat */
    std::string operator()( const std::string & input )
    {
        // perform the actual encryption / decryption
        const int nb_bytes_treated =
            m_cipher_function(
                input.size(),
                reinterpret_cast< const unsigned char * >( input.data() ),
                m_buffer.get(),
                *m_key,
                RSA_PKCS1_OAEP_PADDING );

        check_errors();

        if ( nb_bytes_treated == -1 )
            throw cannot_encrypt_or_decrypt( ERR_reason_error_string( ERR_get_error() ) );

        assert( static_cast<unsigned>( nb_bytes_treated ) <= m_buffer_size );
        return std::string( reinterpret_cast<char *>( m_buffer.get() ),
                            nb_bytes_treated );
    }

private:
    std::shared_ptr<rsa> m_key;
    const size_t m_buffer_size;
    std::unique_ptr< unsigned char[] > m_buffer;
    std::function< int( int, const unsigned char *, unsigned char *, RSA *, int ) >
    m_cipher_function;
};

std::string cryptor::encrypt( std::string clear_text )
{
    return encrypt_or_decrypt( std::move( clear_text ), true );
}

std::string cryptor::decrypt( std::string crypted_data )
{
    return encrypt_or_decrypt( std::move( crypted_data ), false );
}

std::string cryptor::encrypt_or_decrypt( std::string input, const bool encrypt )
{
    std::shared_ptr<rsa> key = encrypt ? m_keys->public_key()
                               : m_keys->private_key();

    assert( key.get() != nullptr );

    const size_t chunk_size = encrypt ? ( RSA_size( *key ) - 42 )
                              : ( RSA_size( *key ) );

    // split the input string into fix-sized chunks
    std::string output;
    const std::list< std::string > chunks =
        split_string( std::move( input ), chunk_size );

    // process each chunk and append it to the output data
    std::transform( chunks.cbegin(), chunks.cend(),
                    string_appender( output ),
                    block_crypter( key, encrypt ) );

    return output;

}

cryptor::~cryptor() noexcept
{
}

cryptbuf::cryptbuf( std::string encryption_key, std::ostream & ostr )
    : cryptbuf( encryption_key, ostr, "" )
{
}

cryptbuf::cryptbuf( std::string encryption_key, std::ostream & ostr,
                    std::string password )
    : m_cryptor( "" /* no private key */, "" /* no password for that key */,
                 std::move( encryption_key ), std::move( password ) )
    , m_ostr( ostr )
{
}

int cryptbuf::sync()
{
    // encrypt current buffer
    const std::string & current_buffer = str();
    std::string encrypted_buffer = m_cryptor.encrypt( current_buffer );

    // flushes encrypted buffer into the output stream
    m_ostr.write( encrypted_buffer.c_str(), encrypted_buffer.size() );

    return 0;
}

cryptbuf::~cryptbuf() noexcept
{
    try
    {
        sync();
    }
    catch( ... )
    {
    }
}
