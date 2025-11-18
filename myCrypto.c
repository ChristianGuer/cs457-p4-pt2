/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c     SKELETON

Written By: 
     1- YOU  MUST   WRITE 
	 2- FULL NAMES  HERE   (or risk losing points )
Submitted on: 
     Insert the date of Submission here
	 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//
//  ALL YOUR  CODE FORM  PREVIOUS PAs  and pLABs


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

    size_t LenMsg2  ;
    
    //---------------------------------------------------------------------------------------
    // Construct TktPlain = { Ks  || L(IDa)  || IDa }
    // in the global scratch buffer plaintext[]


    // Use that global array as a scratch buffer for building the plaintext of the ticket
    // Compute its encrypted version in the global scratch buffer ciphertext[]

    // Now, set TktCipher = encrypt( Kb , plaintext );
    // Store the result in the global scratch buffer ciphertext[]

    //---------------------------------------------------------------------------------------
    // Construct the rest of Message 2 then encrypt it using Ka
    // MSG2 plain = {  Ks || L(IDb) || IDb  ||  Na || L(TktCipher) || TktCipher }

    // Fill in Msg2 Plaintext:  Ks || L(IDb) || IDb  || L(Na) || Na || lenTktCipher) || TktCipher
    // Reuse that global array plaintext[] as a scratch buffer for building the plaintext of the MSG2

    // Now, encrypt Message 2 using Ka. 
    // Use the global scratch buffer ciphertext2[] to collect the results

    // allocate memory on behalf of the caller for a copy of MSG2 ciphertext

    // Copy the encrypted ciphertext to Caller's msg2 buffer.

    fprintf( log , "The following Encrypted MSG2 ( %lu bytes ) has been"
                   " created by MSG2_new():  \n" ,  ...  ) ;
    BIO_dump_indent_fp( log , ... ,  ...  , 4 ) ;    fprintf( log , "\n" ) ;    

    fprintf( log ,"This is the content of MSG2 ( %lu Bytes ) before Encryption:\n" ,  ... );  
    fprintf( log ,"    Ks { key + IV } (%lu Bytes) is:\n" , KEYSIZE );
    BIO_dump_indent_fp ( log ,  ...  ,  ...  , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    IDb (%lu Bytes) is:\n" , LenB);
    BIO_dump_indent_fp ( log ,  ...  ,  ...  , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    Na (%lu Bytes) is:\n" , NONCELEN);
    BIO_dump_indent_fp ( log ,  ...  ,  ...  , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    Encrypted Ticket (%lu Bytes) is\n" ,  ... );
    BIO_dump_indent_fp ( log ,  ...  ,  ...  , 4 ) ;  fprintf( log , "\n") ; 

    fflush( log ) ;    
    
    return LenMsg2 ;    

}

//-----------------------------------------------------------------------------
// Receive Message #2 by Amal from by the KDC
// Parse the incoming msg2 into the component fields 
// *Ks, *IDb, *Na and TktCipher = Encr{ L(Ks) || Ks  || L(IDa)  || IDa }

void MSG2_receive( FILE *log , int fd , const myKey_t *Ka , myKey_t *Ks, char **IDb , 
                       Nonce_t *Na , size_t *lenTktCipher , uint8_t **tktCipher )
{



    fprintf( log ,"MSG2_receive() got the following Encrypted MSG2 ( %lu bytes ) Successfully\n" 
                 , .... );


}

//-----------------------------------------------------------------------------
// Build a new Message #3 from Amal to Basim
// MSG3 = {  L(TktCipher)  || TktCipher  ||  Na2  }
// No further encryption is done on MSG3
// Returns the size of Message #3  in bytes

size_t MSG3_new( FILE *log , uint8_t **msg3 , const size_t lenTktCipher , const uint8_t *tktCipher,  
                   const Nonce_t *Na2 )
{

    size_t    LenMsg3 ;

    fprintf( log , "The following MSG3 ( %lu bytes ) has been created by "
                   "MSG3_new ():\n" , LenMsg3 ) ;
    BIO_dump_indent_fp( log , *msg3 , LenMsg3 , 4 ) ;    fprintf( log , "\n" ) ;    
    fflush( log ) ;    

    return( LenMsg3 ) ;

}

//-----------------------------------------------------------------------------
// Receive Message #3 by Basim from Amal
// Parse the incoming msg3 into its components Ks , IDa , and Na2
// The buffers for Kb, Ks, and Na2 are pre-created by the caller
// The value of Kb is set by the caller
// The buffer for IDA is to be allocated here into *IDa

void MSG3_receive( FILE *log , int fd , const myKey_t *Kb , myKey_t *Ks , char **IDa , Nonce_t *Na2 )
{



    fprintf( log ,"The following Encrypted TktCipher ( %lu bytes ) was received by MSG3_receive()\n" 
                 , ....  );
    BIO_dump_indent_fp( log , ciphertext , lenTktCipher , 4 ) ;   fprintf( log , "\n");
    fflush( log ) ;



    fprintf( log ,"Here is the Decrypted Ticket ( %lu bytes ) in MSG3_receive():\n" , lenTktPlain ) ;
    BIO_dump_indent_fp( log , decryptext , ..... , 4 ) ;   fprintf( log , "\n");
    fflush( log ) ;



}

//-----------------------------------------------------------------------------
// Build a new Message #4 from Basim to Amal
// MSG4 = Encrypt( Ks ,  { fNa2 ||  Nb }   )
// A new buffer for *msg4 is allocated here
// All other arguments have been initialized by caller

// Returns the size of Message #4 after being encrypted by Ks in bytes

size_t  MSG4_new( FILE *log , uint8_t **msg4, const myKey_t *Ks , Nonce_t *fNa2 , Nonce_t *Nb )
{

    size_t LenMsg4 ;

    // Construct MSG4 Plaintext = { f(Na2)  ||  Nb }
    // Use the global scratch buffer plaintext[] for MSG4 plaintext and fill it in with component values


    // Now, encrypt MSG4 plaintext using the session key Ks;
    // Use the global scratch buffer ciphertext[] to collect the result. Make sure it fits.

    // Now allocate a buffer for the caller, and copy the encrypted MSG4 to it
    *msg4 = malloc( .... ) ;



    
    fprintf( log , "The following Encrypted MSG4 ( %lu bytes ) has been"
                   " created by MSG4_new ():  \n" , LenMsg4 ) ;
    BIO_dump_indent_fp( log , *msg4 , ... ) ;

    return LenMsg4 ;
    

}

//-----------------------------------------------------------------------------
// Receive Message #4 by Amal from Basim
// Parse the incoming encrypted msg4 into the values rcvd_fNa2 and Nb

void  MSG4_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *rcvd_fNa2 , Nonce_t *Nb )
{


}

//-----------------------------------------------------------------------------
// Build a new Message #5 from Amal to Basim
// A new buffer for *msg5 is allocated here
// MSG5 = Encr( Ks  ,  { fNb }  )
// All other arguments have been initialized by caller
// Returns the size of Message #5  in bytes

size_t  MSG5_new( FILE *log , uint8_t **msg5, const myKey_t *Ks ,  Nonce_t *fNb )
{
    size_t  LenMSG5cipher  ;

    // Construct MSG5 Plaintext  = {  f(Nb)  }
    // Use the global scratch buffer plaintext[] for MSG5 plaintext. Make sure it fits 


    // Now, encrypt( Ks , {plaintext} );
    // Use the global scratch buffer ciphertext[] to collect result. Make sure it fits.


    // Now allocate a buffer for the caller, and copy the encrypted MSG5 to it
    *msg5 = malloc( ... ) ;


    fprintf( log , "The following Encrypted MSG5 ( %lu bytes ) has been"
                   " created by MSG5_new ():  \n" , LenMSG5cipher ) ;
    BIO_dump_indent_fp( log , *msg5 , LenMSG5cipher , 4 ) ;    fprintf( log , "\n" ) ;    
    fflush( log ) ;    

    return LenMSG5cipher ;

}

//-----------------------------------------------------------------------------
// Receive Message 5 by Basim from Amal
// Parse the incoming msg5 into the value fNb

void  MSG5_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *fNb )
{

    size_t    LenMSG5cipher ;
    
    // Read Len( Msg5 ) followed by reading Msg5 itself
    // Always make sure read() and write() succeed
    // Use the global scratch buffer ciphertext[] to receive encrypted MSG5.
    // Make sure it fits.


    fprintf( log ,"The following Encrypted MSG5 ( %lu bytes ) has been received:\n" , LenMSG5cipher );


    // Now, Decrypt MSG5 using Ks
    // Use the global scratch buffer decryptext[] to collect the results of decryption
    // Make sure it fits


    // Parse MSG5 into its components f( Nb )



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
}
