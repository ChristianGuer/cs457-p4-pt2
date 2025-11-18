/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.h

              D O    N O T    M O D I F Y     T H I S    F I L E
Written By: 
     1- Mohamed Aboutabl

----------------------------------------------------------------------------*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <linux/random.h>
#include <assert.h>
#include <arpa/inet.h>

/* OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

// For symmetric-key Encryption/Decryption, 
// use a 256-bit key and AES in CBC mode (with a 128-bit IV)
// Ensure the (key,IV) being used match the specified algorithm
#define ALGORITHM          EVP_aes_256_cbc
#define SYMMETRIC_KEY_LEN  32
#define INITVECTOR_LEN     16

#define HASH_ALGORITHM     EVP_sha512
#define HASH_LEN           64

//***********************************************************************
// pLAB-01
//***********************************************************************

#define CIPHER_LEN_MAX     2048
#define PLAINTEXT_LEN_MAX (CIPHER_LEN_MAX - 32)
#define DECRYPTED_LEN_MAX (CIPHER_LEN_MAX)

void       handleErrors( char *msg ) ;

unsigned   encrypt( uint8_t *pPlainText, unsigned plainText_len, 
                    const uint8_t *key, const uint8_t *iv, uint8_t *pCipherText ) ;

unsigned   decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
                    const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText) ;

//***********************************************************************
// PA-01
//***********************************************************************

int    encryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv );
int    decryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv );

//***********************************************************************
// pLAB-02
//***********************************************************************

EVP_PKEY    *getRSAfromFile(char * filename, int public) ;

//***********************************************************************
// PA-02
//***********************************************************************

int privKeySign( uint8_t **sig , size_t *sigLen , EVP_PKEY  *privKey 
           , uint8_t *in , size_t inLen )  ;

int pubKeyVerify( uint8_t *sig , size_t sigLen , EVP_PKEY  *pubKey 
           , uint8_t *data , size_t dataLen ) ;
          
size_t fileDigest( int fd_in , int fd_out , uint8_t *digest ) ;

/***********************************************************************
// PA-03
//
***********************************************************************/



//***********************************************************************
// PA-04   Part  ONE
//***********************************************************************

typedef  uint32_t       Nonce_t[ 1 ] ; 
typedef  uint8_t       *uCharPtr ;

// Key Object = symmetricKey || IV in one structure for easier argument passing
typedef struct {
            uint8_t  key[ SYMMETRIC_KEY_LEN ] , 
                     iv [ INITVECTOR_LEN ] ;
        }  myKey_t ; 

#define NONCELEN       ( sizeof( Nonce_t )  )
#define LENSIZE        ( sizeof( size_t  )  )
#define KEYSIZE        ( sizeof( myKey_t )  )

#define BANNER(f) fprintf( (f) , "***************************************************\n")

void     exitError( char *errText ) ;
int      getKeyFromFile( char *keyF , myKey_t *x ) ;

size_t   MSG1_new( FILE *log , uint8_t **msg1 , const char *IDa , const char *IDb 
                   , const Nonce_t Na ) ;

void     MSG1_receive( FILE *log , int fd , char **IDa , char **IDb , Nonce_t Na ) ;

//***********************************************************************
// PA-04   Part  TWO
//***********************************************************************

size_t MSG2_new( FILE * log , uint8_t **msg2 , const myKey_t *Ka , const myKey_t *Kb , 
                   const myKey_t *Ks , const char *IDa , const char *IDb , Nonce_t *Na ) ;

void     MSG2_receive( FILE *log , int fd , const myKey_t *Ka , myKey_t *Ks, char **IDb , 
                       Nonce_t *Na , size_t *lenTktCipher , uint8_t **tktCipher ) ;

size_t   MSG3_new( FILE *log , uint8_t **msg3 , const size_t lenTktCipher , const uint8_t *tktCipher, 
                   const Nonce_t *Na2 ) ;

void     MSG3_receive( FILE *log , int fd , const myKey_t *Kb , myKey_t *Ks , char **IDa , Nonce_t *Na2 ) ;

size_t   MSG4_new( FILE *log , uint8_t **msg4, const myKey_t *Ks , Nonce_t *fNa2 , Nonce_t *Nb ) ;

void     MSG4_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *rcvd_fNa2 , Nonce_t *Nb ) ;

size_t   MSG5_new( FILE *log , uint8_t **msg5, const myKey_t *Ks ,  Nonce_t *fNb ) ;

void     MSG5_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *fNb ) ;

void     fNonce( Nonce_t r , Nonce_t n ) ;

