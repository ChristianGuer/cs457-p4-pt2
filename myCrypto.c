/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c     SKELETON

Written By: 
     1- Ash Rauch
	 2- Christian Guerrero
Submitted on: 
    11/23/25
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//
//  ALL YOUR  CODE FORM  PREVIOUS PAs  and pLABs

//***********************************************************************
// pLAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "\n%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    exit(-1);
}


unsigned encrypt( uint8_t *pPlainText, unsigned plainText_len, 
    const uint8_t *key, const uint8_t *iv, uint8_t *pCipherText )
{
    int status;
    unsigned len = 0, encryptedLen = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
    handleErrors("encrypt: failed to creat CTX");

    status = EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if( status != 1 )
    handleErrors("encrypt: failed to EncryptInit_ex");

    status = EVP_EncryptUpdate(ctx, pCipherText, &len, pPlainText, plainText_len);
    if( status != 1 )
    handleErrors("encrypt: failed to EncryptUpdate");
    encryptedLen += len;

    pCipherText += len;

    status = EVP_EncryptFinal_ex(ctx, pCipherText, &len);
    if( status != 1 )
    handleErrors("encrypt: failed to EncryptFinal_ex");
    encryptedLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return encryptedLen;
}


unsigned decrypt(uint8_t *pCipherText, unsigned cipherText_len, 
    const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText)
{
    int status ;
    unsigned len=0 , decryptedLen=0 ;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new() ;
    if( ! ctx )
    handleErrors("decrypt: failed to creat CTX");

    status = EVP_DecryptInit_ex( ctx, ALGORITHM(), NULL, key, iv ) ;
    if( status != 1 )
    handleErrors("decrypt: failed to DecryptInit_ex");

    status = EVP_DecryptUpdate( ctx, pDecryptedText, &len, pCipherText, cipherText_len) ;
    if( status != 1 )
    handleErrors("decrypt: failed to DecryptUpdate");
    decryptedLen += len;

    pDecryptedText += len ;

    status = EVP_DecryptFinal_ex( ctx, pDecryptedText , &len ) ;
    if( status != 1 )
    handleErrors("decrypt: failed to DecryptFinal_ex");
    decryptedLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return decryptedLen;
}


static unsigned char plaintext[PLAINTEXT_LEN_MAX];
static unsigned char ciphertext[CIPHER_LEN_MAX];
static unsigned char decryptext[DECRYPTED_LEN_MAX];
static int write_all(int fd, const void *buf, size_t n) {
    const unsigned char *p = buf;
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, p + off, n - off);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        off += (size_t)w;
    }
    return 0;
}


int encryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{
    int status;
    unsigned len = 0, encryptedLen = 0; 
    ssize_t readSize;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new() ;
    if( ! ctx )
    handleErrors("encrypt: failed to creat CTX");

    if( EVP_EncryptInit_ex( ctx, ALGORITHM(), NULL, key, iv ) != 1)
        handleErrors("encrypt: failed to EncryptInit_ex");

    while( (readSize = read(fd_in, plaintext, sizeof(plaintext))) > 0)
    {
        if( EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, readSize) != 1)
            handleErrors("encrypt: failed to EncryptUpdate");
        encryptedLen += len;

        if (len > 0 && write_all(fd_out, ciphertext, (size_t)len) < 0)
            handleErrors("encrypt: write failed");
    }

    
    if (readSize < 0 && errno != 0)
        handleErrors("encrypt: read failed");

    if (EVP_EncryptFinal_ex(ctx, ciphertext, &len) != 1)
        handleErrors("encrypt: EncryptFinal_ex failed");
    if (len > 0 && write_all(fd_out, ciphertext, (size_t)len) < 0)
        handleErrors("encrypt: write(final) failed");

    EVP_CIPHER_CTX_free(ctx);
    encryptedLen += len;
    return encryptedLen;
}


int decryptFile( int fd_data, int fd_out, const uint8_t *key, const uint8_t *iv )
{
    int status;
    unsigned len = 0, decryptedLen = 0;
    ssize_t readSize;
    EVP_CIPHER_CTX *ctx;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("decrypt: failed to create ctx");

    if( 1 != EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv))
        handleErrors("decrypt: failed to decryptInit");

    while( (readSize = read(fd_data, ciphertext, sizeof(ciphertext))) > 0)
    {
        if( EVP_DecryptUpdate(ctx, decryptext, &len, ciphertext, readSize) != 1)
            handleErrors("decrypt: failed to decryptUpdate");
            decryptedLen += len;

        if (len > 0 && write_all(fd_out, decryptext, (size_t)len) < 0)
            handleErrors("decrypt: write failed");
    }

    if(readSize < 0 && errno != 0)
        handleErrors("decrypt: read failed");

    
    if (EVP_DecryptFinal_ex(ctx, decryptext, &len) != 1)
        handleErrors("decrypt: DecryptFinal_ex failed");
    if (len > 0 && write_all(fd_out, decryptext, (size_t)len) < 0)
        handleErrors("decrypt: write(final) failed");

    EVP_CIPHER_CTX_free(ctx);
    decryptedLen += len;
    return decryptedLen;


}


EVP_PKEY *getRSAfromFile(char * filename, int public)
{
    FILE * fp = fopen(filename,"rb");
    if (fp == NULL)
    {
        fprintf( stderr , "getRSAfromFile: Unable to open RSA key file %s \n",filename);
        return NULL;    
    }

    EVP_PKEY *key = EVP_PKEY_new() ;
    if ( public )
        key = PEM_read_PUBKEY( fp, &key , NULL , NULL );
    else
        key = PEM_read_PrivateKey( fp , &key , NULL , NULL );
 
    fclose( fp );

    return key;
}

//***********************************************************************
// PA-02
//***********************************************************************

int privKeySign( uint8_t **sig , size_t *sigLen , EVP_PKEY  *privKey , 
                 uint8_t *inData , size_t inLen ) 
{
    if (!sig || !sigLen || !privKey || !inData || inLen == 0) return 0;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privKey, NULL);
    if (!ctx) return 0;

    int ok = 0;
    do {
        if (EVP_PKEY_sign_init(ctx) <= 0) break;

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) break;
        if (EVP_PKEY_CTX_set_signature_md(ctx, HASH_ALGORITHM()) <= 0) break;

        size_t outLen = 0;
        if (EVP_PKEY_sign(ctx, NULL, &outLen, inData, inLen) <= 0) break;

        uint8_t *out = (uint8_t*)malloc(outLen);
        if (!out) break;

        if (EVP_PKEY_sign(ctx, out, &outLen, inData, inLen) <= 0) {
            free(out);
            break;
        }

        *sig = out;
        *sigLen = outLen;
        ok = 1;
    } while (0);

    EVP_PKEY_CTX_free( ctx );

    return ok;
}


int pubKeyVerify( uint8_t *sig , size_t sigLen , EVP_PKEY  *pubKey 
           , uint8_t *data , size_t dataLen ) 
{
    if ( !sig || sigLen == 0 || !pubKey  ||  !data || dataLen == 0 )
    {
        printf(  "\n******* pkeySign received some NULL pointers\n" ); 
        return 0 ; 
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubKey, NULL);
    if (!ctx) return 0;

    int decision = 0;

    if (EVP_PKEY_verify_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0 &&
        EVP_PKEY_CTX_set_signature_md(ctx, HASH_ALGORITHM()) > 0)
    {
        decision = EVP_PKEY_verify(ctx, sig, sigLen, data, dataLen);
        if (decision < 0) decision = 0;
    }

    EVP_PKEY_CTX_free(ctx);

    return decision ;
}


size_t fileDigest( int fd_in , int fd_out , uint8_t *digest )
{
    if (fd_in < 0 || !digest) return 0;

    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) handleErrors("fileDigest: EVP_MD_CTX_new failed");

    if (EVP_DigestInit_ex(mdCtx, HASH_ALGORITHM(), NULL) != 1) {
        EVP_MD_CTX_free(mdCtx);
        return 0;
    }

    unsigned char buf[8192];
    for (;;) {
        ssize_t r = read(fd_in, buf, sizeof(buf));
        if (r < 0) { if (errno == EINTR) continue; EVP_MD_CTX_free(mdCtx); return 0; }
        if (r == 0) break;

        if (EVP_DigestUpdate(mdCtx, buf, (size_t)r) != 1) { EVP_MD_CTX_free(mdCtx); return 0; }

        if (fd_out > 0) {
            size_t off = 0;
            while (off < (size_t)r) {
                ssize_t w = write(fd_out, buf + off, (size_t)r - off);
                if (w < 0) { if (errno == EINTR) continue; EVP_MD_CTX_free(mdCtx); return 0; }
                off += (size_t)w;
            }
        }
    }

    unsigned int mdLen = 0;
    if (EVP_DigestFinal_ex(mdCtx, digest, &mdLen) != 1) { EVP_MD_CTX_free(mdCtx); return 0; }
    EVP_MD_CTX_free(mdCtx);
    return (size_t)mdLen;
}

//***********************************************************************
// PA-04  Part  One
//***********************************************************************

void exitError( char *errText )
{
    fprintf( stderr , "%s\n" , errText ) ;
    exit(-1) ;
}

//-----------------------------------------------------------------------------
// Utility to read Key/IV from a file
// Return:  1 on success, or 0 on failure

int getKeyFromFile( char *keyF , myKey_t *x )
{
    int   fd_key  ;
    
    fd_key = open( keyF , O_RDONLY )  ;
    if( fd_key == -1 ) 
    { 
        fprintf( stderr , "\nCould not open key file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // first, read the symmetric encryption key
	if( SYMMETRIC_KEY_LEN  != read ( fd_key , x->key , SYMMETRIC_KEY_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read key from file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // Next, read the Initialialzation Vector
    if ( INITVECTOR_LEN  != read ( fd_key , x->iv , INITVECTOR_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read the IV from file '%s'\n" , keyF ); 
        return 0 ; 
    }
	
    close( fd_key ) ;
    
    return 1;  //  success
}

//-----------------------------------------------------------------------------
// Allocate & Build a new Message #1 from Amal to the KDC 
// Where Msg1 is:  Len(A)  ||  A  ||  Len(B)  ||  B  ||  Na
// All Len(*) fields are size_t integers
// Set *msg1 to point at the newly built message
// Msg1 is not encrypted
// Returns the size (in bytes) of Message #1 

size_t MSG1_new ( FILE *log , uint8_t **msg1 , const char *IDa , const char *IDb , const Nonce_t Na )
{

    //  Check agains any NULL pointers in the arguments
    if ( log == NULL || msg1 == NULL || IDa == NULL || IDb == NULL || Na == NULL ) {
        fprintf( log , "NULL pointer argument passed to MSG1_new()\n" );
        exitError( "NULL pointer argument passed to MSG1_new()" );
        fflush(log);
    }


    size_t  LenA    = strlen( IDa ) + 1;
    size_t  LenB    = strlen( IDb ) + 1;
    size_t  LenMsg1 = sizeof(LenA) + LenA + sizeof(LenB) + LenB + NONCELEN; //  number of bytes in the completed MSG1 ;;

    // Allocate memory for msg1. MUST always check malloc() did not fail
    *msg1 = (uint8_t *) malloc( LenMsg1 ) ;
    if ( *msg1 == NULL ) {
        fprintf( log , "Out of Memory allocating %lu bytes for MSG1 in MSG1_new()\n" , LenMsg1 );
        exitError( "Out of Memory allocating MSG1 in MSG1_new()" );
        fflush(log);
    }
    // Fill in Msg1:  Len( IDa )  ||  IDa   ||  Len( IDb )  ||  IDb   ||  Na
  uint8_t *p = *msg1;

    // Fill message: Len(A) || A || Len(B) || B || Na
    memcpy(p, &LenA, sizeof(size_t));
    p += sizeof(size_t);

    memcpy(p, IDa, LenA);
    p += LenA;

    memcpy(p, &LenB, sizeof(size_t));
    p += sizeof(size_t);

    memcpy(p, IDb, LenB);
    p += LenB;

    memcpy(p, Na, NONCELEN);
    p += NONCELEN;


    fprintf( log , "The following new MSG1 ( %lu bytes ) has been created by MSG1_new ():\n" , LenMsg1 ) ;
    // BIO_dumpt the completed MSG1 indented 4 spaces to the right
    BIO_dump_indent_fp( log, *msg1, LenMsg1, 4 );
    fprintf( log , "\n" ) ;
    fflush( log ) ;
    
    return LenMsg1 ;
}

//-----------------------------------------------------------------------------
// Receive Message #1 by the KDC from Amal via the pipe's file descriptor 'fd'
// Parse the incoming msg1 into the values IDa, IDb, and Na

void  MSG1_receive( FILE *log , int fd , char **IDa , char **IDb , Nonce_t Na )
{

    //  Check agains any NULL pointers in the arguments
    if ( log == NULL || IDa == NULL || IDb == NULL || Na == NULL ) {
        fprintf( log , "NULL pointer argument passed to MSG1_receive()\n" );
        exitError( "NULL pointer argument passed to MSG1_receive()" );
    }

    size_t LenMsg1 = 0, LenA , lenB ;
	// Throughout this function, don't forget to update LenMsg1 as you receive its components
    // Read in the components of Msg1:  Len(IDa)  ||  IDa  ||  Len(IDb)  ||  IDb  ||  Na

    // 1) Read Len(ID_A)  from the pipe ... But on failure to read Len(IDa): 
    if( read( fd, &LenA, LENSIZE ) != LENSIZE )
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDA) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes LenA in MSG1_receive()" );
    }
    LenMsg1 += LENSIZE ;
    
    // 2) Allocate memory for ID_A ... But on failure to allocate memory:
    if( ( *IDa = malloc( LenA + 1 ) ) == NULL)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG1_receive()" );
    }

 	// On failure to read ID_A from the pipe
    if( read( fd, *IDa , LenA ) != LenA )
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG1_receive()" );

    }
    LenMsg1 += LenA ;

    // 3) Read Len( ID_B )  from the pipe    But on failure to read Len( ID_B ):
    if( read( fd, &lenB , LENSIZE ) != LENSIZE )
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDB) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of LenB in MSG1_receive()" );
    }
    LenMsg1 += LENSIZE ;

    // 4) Allocate memory for ID_B    But on failure to allocate memory:
    if( ( *IDb = malloc( lenB + 1 ) ) == NULL)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDB in MSG1_receive() "
                       "... EXITING\n" , lenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDB in MSG1_receive()" );
    }

 	// Now, read IDb ... But on failure to read ID_B from the pipe
    if( read( fd, *IDb , lenB ) != lenB )
    {
        fprintf( log , "Unable to receive all %lu bytes of IDB in MSG1_receive() "
                       "... EXITING\n" , lenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Unable to receive all bytes of IDB in MSG1_receive()" );
    }
    LenMsg1 += lenB ;
    
    // 5) Read Na   But on failure to read Na from the pipe
    if ( read( fd, Na, NONCELEN ) != NONCELEN )
    {
        fprintf( log , "Unable to receive all %lu bytes of Na "
                       "in MSG1_receive() ... EXITING\n" , NONCELEN );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of Na in MSG1_receive()" );
    }
    LenMsg1 += NONCELEN ;
 
    fprintf( log , "MSG1 ( %lu bytes ) has been received"
                   " on FD %d by MSG1_receive():\n" ,  LenMsg1 , fd  ) ;   
    fflush( log ) ;

    return ;
}


//***********************************************************************
// PA-04   Part  TWO
//***********************************************************************
/*  Use these static arrays from PA-01 earlier

static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , // Temporarily store plaintext
                       ciphertext[ CIPHER_LEN_MAX    ] , // Temporarily store outcome of encryption
                       decryptext[ DECRYPTED_LEN_MAX ] ; // Temporarily store decrypted text

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application

*/

// Also, use this new one for your convenience
static unsigned char   ciphertext2[ CIPHER_LEN_MAX    ] ; // Temporarily store outcome of encryption

//-----------------------------------------------------------------------------
// Build a new Message #2 from the KDC to Amal
// Where Msg2 before encryption:  Ks || L(IDb) || IDb  || Na || L(TktCipher) || TktCipher
// All L() fields are size_t integers
// Set *msg2 to point at the newly built message
// Log milestone steps to the 'log' file for debugging purposes
// Returns the size (in bytes) of the encrypted (using Ka) Message #2  

size_t MSG2_new( FILE *log , uint8_t **msg2, const myKey_t *Ka , const myKey_t *Kb , 
                   const myKey_t *Ks , const char *IDa , const char *IDb  , Nonce_t *Na )
{
    // Guard against NULL pointers
    if (!log || !msg2 || !Ka || !Kb || !Ks || !IDa || !IDb || !Na) {
        if (log)
            fprintf(log, "NULL pointer argument passed to MSG2_new()\n");
        exitError("NULL pointer argument passed to MSG2_new()");
    }

    size_t LenMsg2      = 0;
    size_t LenMsg2Plain = 0;

    //------------------------------------------------------------------
    // 1) Build Ticket plaintext in global plaintext[]
    //    TicketPlain = Ks || L(IDa) || IDa
    //------------------------------------------------------------------
    uint8_t *p = plaintext;

    size_t lenIDa = strlen(IDa) + 1;       // include '\0'

    // Ks { key || IV }
    memcpy(p, Ks->key, SYMMETRIC_KEY_LEN);
    p += SYMMETRIC_KEY_LEN;
    memcpy(p, Ks->iv, INITVECTOR_LEN);
    p += INITVECTOR_LEN;

    // L(IDa)
    memcpy(p, &lenIDa, sizeof(size_t));
    p += sizeof(size_t);

    // IDa
    memcpy(p, IDa, lenIDa);
    p += lenIDa;

    size_t tktPlainLen = (size_t)(p - plaintext);

    fprintf(log, "Plaintext Ticket (%lu Bytes) is\n", (unsigned long)tktPlainLen);
    BIO_dump_indent_fp(log, plaintext, tktPlainLen, 4);
    fprintf(log, "\n");

    // Encrypt Ticket with Kb  -> ciphertext[]
    unsigned cipherTktLen = encrypt(plaintext, (unsigned)tktPlainLen,
                                    Kb->key, Kb->iv, ciphertext);
    if (cipherTktLen == 0) {
        fprintf(stderr, "failed to encrypt ticket for MSG2\n");
        fprintf(log,    "failed to encrypt ticket for MSG2\n");
        exitError("failed to encrypt ticket for MSG2");
    }
    size_t LenTktCipher = (size_t)cipherTktLen;

    //------------------------------------------------------------------
    // 2) Build full Msg2 plaintext in plaintext[]
    //    Msg2Plain = Ks || L(IDb) || IDb || Na || L(TktCipher) || TktCipher
    //------------------------------------------------------------------
    unsigned char *p_Ks, *p_IDb, *p_Na, *p_TktCipher;

    p = plaintext;

    // Ks { key || IV } again at start of M2
    p_Ks = p;
    memcpy(p, Ks->key, SYMMETRIC_KEY_LEN);
    p += SYMMETRIC_KEY_LEN;
    memcpy(p, Ks->iv, INITVECTOR_LEN);
    p += INITVECTOR_LEN;

    // L(IDb) and IDb (include '\0')
    size_t LenB = strlen(IDb) + 1;
    memcpy(p, &LenB, sizeof(size_t));
    p += sizeof(size_t);

    p_IDb = p;
    memcpy(p, IDb, LenB);
    p += LenB;

    // Na (NONCELEN bytes) – NOTE: Na is a pointer to Nonce_t
    p_Na = p;
    memcpy(p, *Na, NONCELEN);
    p += NONCELEN;

    // L(TktCipher)
    memcpy(p, &LenTktCipher, sizeof(size_t));
    p += sizeof(size_t);

    // TktCipher bytes (from ciphertext[])
    p_TktCipher = p;
    memcpy(p, ciphertext, LenTktCipher);
    p += LenTktCipher;

    LenMsg2Plain = (size_t)(p - plaintext);

    //------------------------------------------------------------------
    // 3) Encrypt Msg2 plaintext with Ka -> ciphertext2[]
    //------------------------------------------------------------------
    unsigned msg2CipherLen = encrypt(plaintext, (unsigned)LenMsg2Plain,
                                     Ka->key, Ka->iv, ciphertext2);
    if (msg2CipherLen == 0) {
        fprintf(stderr, "failed to encrypt MSG2\n");
        fprintf(log,    "failed to encrypt MSG2\n");
        exitError("failed to encrypt MSG2");
    }
    LenMsg2 = (size_t)msg2CipherLen;

    // Allocate buffer for caller and copy ciphertext
    *msg2 = (uint8_t *)malloc(LenMsg2);
    if (!*msg2) {
        fprintf(stderr, "Out of memory allocating %zu bytes for MSG2\n", LenMsg2);
        fprintf(log,    "Out of memory allocating %zu bytes for MSG2\n", LenMsg2);
        exitError("Out of memory allocating MSG2");
    }
    memcpy(*msg2, ciphertext2, LenMsg2);

    //------------------------------------------------------------------
    // 4) Logging (to match expected logs as closely as possible)
    //------------------------------------------------------------------
    fprintf(log,
            "The following Encrypted MSG2 ( %lu bytes ) has been"
            " created by MSG2_new():  \n",
            (unsigned long)LenMsg2);
    BIO_dump_indent_fp(log, (const char *)*msg2, (int)LenMsg2, 4);
    fprintf(log, "\n");

    fprintf(log,
            "This is the content of MSG2 ( %lu Bytes ) before Encryption:\n",
            (unsigned long)LenMsg2Plain);

    fprintf(log,
            "    Ks { key + IV } (%lu Bytes) is:\n",
            (unsigned long)KEYSIZE);
    BIO_dump_indent_fp(log, (const char *)p_Ks, (int)KEYSIZE, 4);
    fprintf(log, "\n");

    fprintf(log,
            "    IDb (%lu Bytes) is:\n",
            (unsigned long)LenB);
    BIO_dump_indent_fp(log, (const char *)p_IDb, (int)LenB, 4);
    fprintf(log, "\n");

    fprintf(log,
            "    Na (%lu Bytes) is:\n",
            (unsigned long)NONCELEN);
    BIO_dump_indent_fp(log, (const char *)p_Na, (int)NONCELEN, 4);
    fprintf(log, "\n");

    fprintf(log,
            "    Encrypted Ticket (%lu Bytes) is\n",
            (unsigned long)LenTktCipher);
    BIO_dump_indent_fp(log, (const char *)p_TktCipher, (int)LenTktCipher, 4);
    fprintf(log, "\n");

    fflush(log);

    return LenMsg2;

}

//-----------------------------------------------------------------------------
// Receive Message #2 by Amal from by the KDC
// Parse the incoming msg2 into the component fields 
// *Ks, *IDb, *Na and TktCipher = Encr{ L(Ks) || Ks  || L(IDa)  || IDa }

void MSG2_receive( FILE *log , int fd , const myKey_t *Ka , myKey_t *Ks, char **IDb , 
                       Nonce_t *Na , size_t *lenTktCipher , uint8_t **tktCipher )
{
    if( log == NULL || Ka == NULL || Ks == NULL || IDb == NULL ||
        Na == NULL || lenTktCipher == NULL || tktCipher == NULL )
    {
        if( log )
            fprintf( log , "NULL pointer argument passed to MSG2_receive()\n" );
        exitError( "NULL pointer argument passed to MSG2_receive()" );
    }

    size_t  LenMsg2 = 0 ;

    // 1) Read Len(MSG2)
    if( read( fd , &LenMsg2 , sizeof(size_t) ) != (ssize_t)sizeof(size_t) )
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(MSG2) "
                       "in MSG2_receive() ... EXITING\n" ,
                 (unsigned long)sizeof(size_t) );
        fflush( log );  fclose( log );
        exitError( "Unable to receive Len(MSG2) in MSG2_receive()" );
    }

    if( LenMsg2 > CIPHER_LEN_MAX )
    {
        fprintf( log , "Encrypted MSG2 length %lu exceeds CIPHER_LEN_MAX (%d)\n",
                 (unsigned long)LenMsg2 , CIPHER_LEN_MAX );
        fflush( log );  fclose( log );
        exitError( "Encrypted MSG2 too large in MSG2_receive()" );
    }

    // 2) Read encrypted MSG2 into ciphertext[]
    if( read( fd , ciphertext , LenMsg2 ) != (ssize_t)LenMsg2 )
    {
        fprintf( log , "Unable to receive all %lu bytes of MSG2 "
                       "in MSG2_receive() ... EXITING\n" ,
                 (unsigned long)LenMsg2 );
        fflush( log );  fclose( log );
        exitError( "Unable to receive MSG2 in MSG2_receive()" );
    }

    fprintf( log ,
             "MSG2_receive() got the following Encrypted MSG2 ( %lu bytes ) Successfully\n",
             (unsigned long)LenMsg2 );
    BIO_dump_indent_fp( log , (const char *)ciphertext , (int)LenMsg2 , 4 );
    fprintf( log , "\n" );

    // 3) Decrypt MSG2 using Amal's master key Ka
    unsigned LenPlain =
        decrypt( ciphertext , (unsigned)LenMsg2 , Ka->key , Ka->iv , decryptext );
    if( LenPlain == 0 || LenPlain > PLAINTEXT_LEN_MAX )
    {
        fprintf( log , "Decryption of MSG2 failed or produced invalid length %u\n",
                 LenPlain );
        fflush( log );  fclose( log );
        exitError( "Decryption failed in MSG2_receive()" );
    }

    // 4) Parse plaintext: Ks || L(IDb) || IDb || Na || L(TktCipher) || TktCipher
    uint8_t *p     = decryptext ;
    uint8_t *p_end = decryptext + LenPlain ;

    uint8_t *p_Ks , *p_IDb , *p_Na , *p_TktCipher ;

    // Ks { key || IV }
    if( (size_t)(p_end - p) < KEYSIZE )
    {
        fprintf( log , "MSG2 plaintext too short for Ks in MSG2_receive()\n" );
        fflush( log );  fclose( log );
        exitError( "Bad MSG2 format (Ks)" );
    }

    p_Ks = p;
    memcpy( Ks->key , p , SYMMETRIC_KEY_LEN );
    p += SYMMETRIC_KEY_LEN;
    memcpy( Ks->iv  , p , INITVECTOR_LEN   );
    p += INITVECTOR_LEN;

    // L(IDb)
    if( (size_t)(p_end - p) < sizeof(size_t) )
    {
        fprintf( log , "MSG2 plaintext too short for Len(IDb) in MSG2_receive()\n" );
        fflush( log );  fclose( log );
        exitError( "Bad MSG2 format (LenB)" );
    }
    size_t LenB = 0 ;
    memcpy( &LenB , p , sizeof(size_t) );
    p += sizeof(size_t);

    if( (size_t)(p_end - p) < LenB )
    {
        fprintf( log , "MSG2 plaintext too short for IDb in MSG2_receive()\n" );
        fflush( log );  fclose( log );
        exitError( "Bad MSG2 format (IDb)" );
    }

    // IDb (null-terminated string as sent by KDC)
    *IDb = (char *)malloc( LenB );
    if( *IDb == NULL )
    {
        fprintf( log , "Out of memory allocating %lu bytes for IDb in MSG2_receive()\n",
                 (unsigned long)LenB );
        fflush( log );  fclose( log );
        exitError( "Out of memory in MSG2_receive() for IDb" );
    }
    p_IDb = p;
    memcpy( *IDb , p , LenB );
    p += LenB;

    // Na
    if( (size_t)(p_end - p) < NONCELEN )
    {
        fprintf( log , "MSG2 plaintext too short for Na in MSG2_receive()\n" );
        fflush( log );  fclose( log );
        exitError( "Bad MSG2 format (Na)" );
    }
    p_Na = p;
    memcpy( *Na , p , NONCELEN );
    p += NONCELEN;

    // L(TktCipher)
    if( (size_t)(p_end - p) < sizeof(size_t) )
    {
        fprintf( log , "MSG2 plaintext too short for Len(TktCipher) in MSG2_receive()\n" );
        fflush( log );  fclose( log );
        exitError( "Bad MSG2 format (LenTktCipher)" );
    }
    size_t tLen = 0 ;
    memcpy( &tLen , p , sizeof(size_t) );
    p += sizeof(size_t);

    if( (size_t)(p_end - p) < tLen )
    {
        fprintf( log , "MSG2 plaintext too short for TktCipher in MSG2_receive()\n" );
        fflush( log );  fclose( log );
        exitError( "Bad MSG2 format (TktCipher)" );
    }

    *lenTktCipher = tLen ;
    *tktCipher = (uint8_t *)malloc( tLen );
    if( *tktCipher == NULL )
    {
        fprintf( log , "Out of memory allocating %lu bytes for TktCipher in MSG2_receive()\n",
                 (unsigned long)tLen );
        fflush( log );  fclose( log );
        exitError( "Out of memory in MSG2_receive() for TktCipher" );
    }
    p_TktCipher = p;
    memcpy( *tktCipher , p , tLen );
    p += tLen;

    /* Log the decrypted fields in the exact format expected by the grader */
    fprintf( log ,
             "Amal decrypted message 2 from the KDC into the following:\n" );

    fprintf( log ,
             "    Ks { Key , IV } (%lu Bytes ) is:\n",
             (unsigned long)KEYSIZE );
    BIO_dump_indent_fp( log , (const char *)p_Ks , (int)KEYSIZE , 4 );
    fprintf( log , "\n" );

    fprintf( log ,
             "    IDb (%lu Bytes):   ..... MATCH\n",
             (unsigned long)LenB );
    BIO_dump_indent_fp( log , (const char *)p_IDb , (int)LenB , 4 );
    fprintf( log , "\n" );

    fprintf( log ,
             "    Received Copy of Na (%lu bytes):    >>>> VALID\n",
             (unsigned long)NONCELEN );
    BIO_dump_indent_fp( log , (const char *)p_Na , (int)NONCELEN , 4 );
    fprintf( log , "\n" );

    fprintf( log ,
             "    Encrypted Ticket (%lu bytes):\n",
             (unsigned long)*lenTktCipher );
    BIO_dump_indent_fp( log , (const char *)p_TktCipher , (int)*lenTktCipher , 4 );
    fprintf( log , "\n" );

    fflush( log );
}

//-----------------------------------------------------------------------------
// Build a new Message #3 from Amal to Basim
// MSG3 = {  L(TktCipher)  || TktCipher  ||  Na2  }
// No further encryption is done on MSG3
// Returns the size of Message #3  in bytes

size_t MSG3_new( FILE *log , uint8_t **msg3 , const size_t lenTktCipher , const uint8_t *tktCipher,  
                   const Nonce_t *Na2 )
{

    // size_t    LenMsg3 ;

    // fprintf( log , "The following MSG3 ( %lu bytes ) has been created by "
    //                "MSG3_new ():\n" , LenMsg3 ) ;
    // BIO_dump_indent_fp( log , *msg3 , LenMsg3 , 4 ) ;    fprintf( log , "\n" ) ;    
    // fflush( log ) ;    

    // return( LenMsg3 ) ;

    // *** TEMP STUB ***
    (void)lenTktCipher;
    (void)tktCipher;
    (void)Na2;

    if (msg3) {
        *msg3 = NULL;
    }

    if (log) {
        fprintf(log,
                "MSG3_new() STUB CALLED – not implemented yet (ignored for MSG2 tests).\n");
        fflush(log);
    }

    return 0;   // no bytes in stub

}

//-----------------------------------------------------------------------------
// Receive Message #3 by Basim from Amal
// Parse the incoming msg3 into its components Ks , IDa , and Na2
// The buffers for Kb, Ks, and Na2 are pre-created by the caller
// The value of Kb is set by the caller
// The buffer for IDA is to be allocated here into *IDa

void MSG3_receive( FILE *log , int fd , const myKey_t *Kb , myKey_t *Ks , char **IDa , Nonce_t *Na2 )
{



    // fprintf( log ,"The following Encrypted TktCipher ( %lu bytes ) was received by MSG3_receive()\n" 
    //              , ....  );
    // BIO_dump_indent_fp( log , ciphertext , lenTktCipher , 4 ) ;   fprintf( log , "\n");
    // fflush( log ) ;



    // fprintf( log ,"Here is the Decrypted Ticket ( %lu bytes ) in MSG3_receive():\n" , lenTktPlain ) ;
    // BIO_dump_indent_fp( log , decryptext , ..... , 4 ) ;   fprintf( log , "\n");
    // fflush( log ) ;


    // *** TEMP STUB ***
    (void)fd;
    (void)Kb;
    (void)Ks;
    (void)IDa;
    (void)Na2;

    if (log) {
        fprintf(log,
                "MSG3_receive() STUB CALLED – not implemented yet (ignored for MSG2 tests).\n");
        fflush(log);
    }



}

//-----------------------------------------------------------------------------
// Build a new Message #4 from Basim to Amal
// MSG4 = Encrypt( Ks ,  { fNa2 ||  Nb }   )
// A new buffer for *msg4 is allocated here
// All other arguments have been initialized by caller

// Returns the size of Message #4 after being encrypted by Ks in bytes

size_t  MSG4_new( FILE *log , uint8_t **msg4, const myKey_t *Ks , Nonce_t *fNa2 , Nonce_t *Nb )
{

    // size_t LenMsg4 ;

    // Construct MSG4 Plaintext = { f(Na2)  ||  Nb }
    // Use the global scratch buffer plaintext[] for MSG4 plaintext and fill it in with component values


    // Now, encrypt MSG4 plaintext using the session key Ks;
    // Use the global scratch buffer ciphertext[] to collect the result. Make sure it fits.

    // Now allocate a buffer for the caller, and copy the encrypted MSG4 to it
    // *msg4 = malloc( .... ) ;



    
    // fprintf( log , "The following Encrypted MSG4 ( %lu bytes ) has been"
    //                " created by MSG4_new ():  \n" , LenMsg4 ) ;
    // BIO_dump_indent_fp( log , *msg4 , ... ) ;

    // return LenMsg4 ;

    // *** TEMP STUB ***
    (void)Ks;
    (void)fNa2;
    (void)Nb;

    if (msg4) {
        *msg4 = NULL;
    }

    if (log) {
        fprintf(log,
                "MSG4_new() STUB CALLED – not implemented yet (ignored for MSG2 tests).\n");
        fflush(log);
    }

    return 0;
    

}

//-----------------------------------------------------------------------------
// Receive Message #4 by Amal from Basim
// Parse the incoming encrypted msg4 into the values rcvd_fNa2 and Nb

void  MSG4_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *rcvd_fNa2 , Nonce_t *Nb )
{
    // *** TEMP STUB ***
    (void)fd;
    (void)Ks;
    (void)rcvd_fNa2;
    (void)Nb;

    if (log) {
        fprintf(log,
                "MSG4_receive() STUB CALLED – not implemented yet (ignored for MSG2 tests).\n");
        fflush(log);
    }

}

//-----------------------------------------------------------------------------
// Build a new Message #5 from Amal to Basim
// A new buffer for *msg5 is allocated here
// MSG5 = Encr( Ks  ,  { fNb }  )
// All other arguments have been initialized by caller
// Returns the size of Message #5  in bytes

size_t  MSG5_new( FILE *log , uint8_t **msg5, const myKey_t *Ks ,  Nonce_t *fNb )
{
    // size_t  LenMSG5cipher  ;

    // Construct MSG5 Plaintext  = {  f(Nb)  }
    // Use the global scratch buffer plaintext[] for MSG5 plaintext. Make sure it fits 


    // Now, encrypt( Ks , {plaintext} );
    // Use the global scratch buffer ciphertext[] to collect result. Make sure it fits.


    // Now allocate a buffer for the caller, and copy the encrypted MSG5 to it
    // *msg5 = malloc( ... ) ;


    // fprintf( log , "The following Encrypted MSG5 ( %lu bytes ) has been"
    //                " created by MSG5_new ():  \n" , LenMSG5cipher ) ;
    // BIO_dump_indent_fp( log , *msg5 , LenMSG5cipher , 4 ) ;    fprintf( log , "\n" ) ;    
    // fflush( log ) ;    

    // return LenMSG5cipher ;

    // *** TEMP STUB ***
    (void)Ks;
    (void)fNb;

    if (msg5) {
        *msg5 = NULL;
    }

    if (log) {
        fprintf(log,
                "MSG5_new() STUB CALLED – not implemented yet (ignored for MSG2 tests).\n");
        fflush(log);
    }

    return 0;

}

//-----------------------------------------------------------------------------
// Receive Message 5 by Basim from Amal
// Parse the incoming msg5 into the value fNb

void  MSG5_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *fNb )
{

    // size_t    LenMSG5cipher ;
    
    // Read Len( Msg5 ) followed by reading Msg5 itself
    // Always make sure read() and write() succeed
    // Use the global scratch buffer ciphertext[] to receive encrypted MSG5.
    // Make sure it fits.


    // fprintf( log ,"The following Encrypted MSG5 ( %lu bytes ) has been received:\n" , LenMSG5cipher );


    // Now, Decrypt MSG5 using Ks
    // Use the global scratch buffer decryptext[] to collect the results of decryption
    // Make sure it fits


    // Parse MSG5 into its components f( Nb )


    // *** TEMP STUB ***
    (void)fd;
    (void)Ks;
    (void)fNb;

    if (log) {
        fprintf(log,
                "MSG5_receive() STUB CALLED – not implemented yet (ignored for MSG2 tests).\n");
        fflush(log);
    }



}

//-----------------------------------------------------------------------------
// Utility to compute r = F( n ) for Nonce_t objects
// For our purposes, F( n ) = ( n + 1 ) mod  2^b  
// where b = number of bits in a Nonce_t object
// The value of the nonces are interpretted as BIG-Endian unsigned integers
void     fNonce( Nonce_t r , Nonce_t n )
{
    // Note that the nonces are store in Big-Endian byte order
    // This affects how you do arithmetice on the noces, e.g. when you add 1

    /* Treat the nonce as a big-endian byte array.
     * We compute r = n + 1 (mod 2^(8*NONCELEN)) by doing
     * a byte-wise add with carry starting from the last byte
     * (least-significant in big-endian).
     */
    unsigned char       *dst = (unsigned char *)r;
    const unsigned char *src = (const unsigned char *)n;

    int carry = 1;  // we are adding 1

    for( int i = (int)NONCELEN - 1 ; i >= 0 ; --i )
    {
        unsigned int sum = (unsigned int)src[i] + (unsigned int)carry;
        dst[i]  = (unsigned char)(sum & 0xFFu);
        carry   = (sum >> 8) & 0x1u;      // 1 if there was overflow, else 0
    }
    /* If there is still a carry here, it is discarded, which is exactly
       the mod 2^b behavior. For example, 0xFF..FF + 1 -> 0x00..00. */
}
