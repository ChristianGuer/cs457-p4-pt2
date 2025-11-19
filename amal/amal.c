/*----------------------------------------------------------------------------
pa-04_PartTwo:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   amal.c

Written By: 
     1- Ash Rauch
	 2- Christian Guerrero
Submitted on: 
    11/23/25
----------------------------------------------------------------------------*/

#include <linux/random.h>
#include <time.h>
#include <stdlib.h>

#include "../myCrypto.h"

// Generate random nonces for Amal
void  getNonce4Amal( int which , Nonce_t  value )
{
	// Normally we generate random nonces using
	// RAND_bytes( (unsigned char *) value , NONCELEN  );
	// However, for grading purpose, we will use fixed values

	switch ( which ) 
	{
		case 1:		// the first nonce
			value[0] = 0x11223344 ;
			break ;

		case 2:		// the second nonce
			value[0] = 0xaabbccdd ;		
			break ;

		default:	// Invalid agrument. Must be either 1 or 2
			fprintf( stderr , "\n\nAmal trying to create an Invalid nonce\n exiting\n\n");
			exit(-1);
	}
}
	
//*************************************
// The Main Loop
//*************************************
int main ( int argc , char * argv[] )
{

    
    
    // Your code from pa-04_PartOne
    int      fd_A2K , fd_K2A , fd_A2B , fd_B2A  ;
    FILE    *log ;

    char *developerName = "Code by Guerrero and Rauch" ;

    /* ---- PA-04 Part Two state for Messages 2+ ---- */
    myKey_t  Ks; // Session key from KDC
    char    *IDb_fromKDC = NULL;
    Nonce_t  Na_fromKDC;
    size_t   lenTktCipher = 0;
    uint8_t *tktCipher    = NULL;

    fprintf( stdout , "Starting Amal's      %s.\n" , developerName  ) ;
    
    if( argc < 5 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. KDC> <sendTo KDC> "
               "<getFr. Basim> <sendTo Basim>\n\n" , argv[0]) ;
        exit(-1) ;
    }
    fd_K2A    = atoi(argv[1]) ;  // Read from KDC    File Descriptor
    fd_A2K    = atoi(argv[2]) ;  // Send to   KDC    File Descriptor
    fd_B2A    = atoi(argv[3]) ;  // Read from Basim  File Descriptor
    fd_A2B    = atoi(argv[4]) ;  // Send to   Basim  File Descriptor

    log = fopen("amal/logAmal.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "\nAmal's  %s. Could not create my log file\n" , developerName  ) ;
        exit(-1) ;
    }

    BANNER( log ) ;
    fprintf( log , "Starting Amal\n" ) ;
    BANNER( log ) ;

    fprintf( log , "\n<readFrom KDC> FD=%d , <sendTo KDC> FD=%d , "
                   "<readFrom Basim> FD=%d , <sendTo Basim> FD=%d\n\n" , 
                   fd_K2A , fd_A2K , fd_B2A , fd_A2B );

    // Get Amal's master key with the KDC
    myKey_t  Ka ;
    if( getKeyFromFile("amal/amalKey.bin", &Ka) == 0)
    {	
        fprintf( stderr , "\nCould not get Amal's Master key & IV.\n" ) ;
        fprintf( log , "\nCould not get Amal's Master key & IV.\n" ) ;
        fclose( log ) ;
        exit(-1) ;
    } else{

        fprintf( log , "Amal has this Master Ka { key , IV }\n" ) ;
        BIO_dump_indent_fp( log , Ka.key , SYMMETRIC_KEY_LEN , 4 ) ;
        fprintf( log , "\n" );
	    // BIO_dump the IV indented 4 spaces to the righ
        BIO_dump_indent_fp( log, Ka.iv, INITVECTOR_LEN, 4 );
        fprintf( log , "\n" );
    }

    // Get Amal's pre-created Nonces: Na and Na2
	Nonce_t   Na , Na2; 
    fprintf( log , "Amal will use these Nonces:  Na  and Na2\n"  ) ;
	// Use getNonce4Amal () to get Amal's 1st and second nonces into Na and Na2, respectively
    getNonce4Amal(1, Na);
    getNonce4Amal(2, Na2);
	// BIO_dump Na indented 4 spaces to the righ
    BIO_dump_indent_fp( log, Na , NONCELEN , 4);
    fprintf( log , "\n" );
	// BIO_dump Na2 indented 4 spaces to the righ
    BIO_dump_indent_fp( log, Na2 , NONCELEN , 4);
    fprintf( log , "\n") ; 

    fflush( log ) ;
    //*************************************
    // Construct & Send    Message 1
    //*************************************
    BANNER( log ) ;
    fprintf( log , "         MSG1 New\n");
    BANNER( log ) ;
    
    char *IDa = "Amal is Hope", *IDb = "Basim is Smiley" ;
    size_t  LenMsg1 ;
    uint8_t  *msg1 ;
    LenMsg1 = MSG1_new( log , &msg1 , IDa , IDb , Na ) ;
    

    
    // Send MSG1 to KDC via the appropriate pipe
    size_t  off = 0 ;
    const uint8_t *p = msg1 ;
    while ( off < LenMsg1 ) {
        ssize_t n = write( fd_A2K, p + off, LenMsg1 - off );
        if ( n < 0 ) {
            fprintf( log , "Amal: Unable to send all %lu bytes of MSG1 to KDC ... EXITING\n" , LenMsg1 );
            fflush( log ) ;  fclose( log ) ;   
            exitError( "Amal: Unable to send all bytes of MSG1 to KDC" );
        }
        off += (size_t)n;
    }

   fprintf( log , "Amal sent message 1 ( %lu bytes ) to the KDC with:\n    "
                   "IDa ='%s'\n    "
                   "IDb = '%s'\n" , LenMsg1 , IDa , IDb ) ;
    fprintf( log , "    Na ( %lu Bytes ) is:\n" , NONCELEN ) ;
    // BIO_dump the nonce Na
    BIO_dump_indent_fp( log, Na , NONCELEN , 4 ) ;
    fprintf( log , "\n" ) ;
    fflush( log ) ;

    // Deallocate any memory allocated for msg1
    free( msg1 ) ;
    msg1 = NULL;

    
    
    
    //*************************************
    // Receive   &   Process Message 2
    //*************************************
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG2 Receive\n");
    BANNER( log ) ;

    /* Call library function to read & decrypt MSG2 from KDC.
       This should:
         - read encrypted MSG2 from fd_K2A
         - decrypt using Ka
         - fill Ks, IDb_fromKDC, Na_fromKDC, lenTktCipher, tktCipher
         - log all the internal fields to logAmal.txt
     */
    MSG2_receive( log,
                  fd_K2A,          // read-from-KDC FD
                  &Ka,             // Amal's master key with KDC
                  &Ks,             // out: session key Ks
                  &IDb_fromKDC,    // out: dynamically allocated IDb string
                  &Na_fromKDC,     // out: Na echoed back
                  &lenTktCipher,   // out: length of ticket cipher
                  &tktCipher );    // out: pointer to ticket cipher buffer

    fflush( log );

    //*************************************
    // Construct & Send    Message 3
    //*************************************
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG3 New\n");
    BANNER( log ) ;

    //*************************************
    // Receive   & Process Message 4
    //*************************************
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG4 Receive\n");
    BANNER( log ) ;

    //*************************************
    // Construct & Send    Message 5
    //*************************************
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG5 New\n");
    BANNER( log ) ;


    //*************************************   
    // Final Clean-Up
    //*************************************  
end_:
    fprintf( log , "\nAmal has terminated normally. Goodbye\n" ) ;  
    fclose( log ) ;
    return 0 ;
}

