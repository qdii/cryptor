#ifndef CRYPTOR_H
#define CRYPTOR_H

#include <exception>
#include <memory> //unique_ptr
#include <string>

/**@brief Exception thrown when an invalid key is used */
struct invalid_key : public std::exception
{
    virtual const char * what() const noexcept override final
    {
        return "The RSA key is invalid";
    }
};

/**@brief Exception thrown when an error occur during encryption */
struct cannot_encrypt : public std::exception
{
    cannot_encrypt()
        : m_reason( "An error occurred while encrypting" )
    {
    }

    cannot_encrypt( const char * const reason )
        : m_reason( reason )
    {
    }

    virtual const char * what() const noexcept override final
    {
        return m_reason;
    }
private:
    const char * const m_reason;
};

/**@brief Exception thrown when an error occur during decryption */
struct cannot_decrypt : public std::exception
{
    cannot_decrypt()
        : m_reason( "An error occurred while decrypting" )
    {
    }

    cannot_decrypt( const char * const reason )
        : m_reason( reason )
    {
    }

    virtual const char * what() const noexcept override final
    {
        return m_reason;
    }
private:
    const char * const m_reason;
};


/**@author Victor Lavaud
 * @class cryptor
 * @brief Class that can encrypt / decrypt strings using asymetric ciphering (RSA)
 */
class cryptor
{
public:
    /**@brief Constructs a cryptor.
     * @param[in] private_key The key used to decipher messages
     * @param[in] public_key The key used to cipher message */
    cryptor( std::string private_key, std::string public_key );

    /**@brief Constructs a cryptor.
     * @param[in] private_key The key used to decipher messages
     * @param[in] private_passwd The password to open the private key (or "")
     * @param[in] public_key The key used to cipher message
     * @param[in] public_passwd The password to open the public key (or "") */
    cryptor( std::string private_key, std::string private_passwd,
             std::string public_key,  std::string public_passwd );

    /**@brief Encrypts a message
     * @param[in] clear_msg The message to encrypt
     * @return An encrypted message built from the clear message and the public key */
    std::string encrypt( std::string clear_msg );

    /**@brief Decrypts a message
     * @param[in] crypted_data The data to decrypt
     * @return A decrypted message built from the crypted message and the private key */
    std::string decrypt( std::string crypted_data );

    /**@brief Destructs a cryptor */
    ~cryptor() noexcept;

private:
    struct rsa_key_pair;
    std::unique_ptr<rsa_key_pair> m_keys;
};

#endif
