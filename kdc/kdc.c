/*----------------------------------------------------------------------------
pa-04_PartTwo:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   kdc.c    SKELETON

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

//*************************************
// The Main Loop
//*************************************
int main ( int argc , char * argv[] )
{

    
    
    // Your code from pa-04_PartOne
    int       fd_A2K , fd_K2A   ;
    FILE     *log ;
    
    char *developerName = "Code by Guerrero and Rauch" ;

    fprintf( stdout , "Starting the KDC's   %s\n"  , developerName ) ;

    if( argc < 3 )
    {
        printf("\nMissing command-line file descriptors: %s <readFrom Amal> "
               "<sendTo Amal>\n\n", argv[0]) ;
        exit(-1) ;
    }

    fd_A2K    = atoi(argv[1]) ;  // Read from Amal   File Descriptor
    fd_K2A    = atoi(argv[2]) ;  // Send to   Amal   File Descriptor

    log = fopen("kdc/logKDC.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "The KDC's   %s. Could not create log file\n"  , developerName ) ;
        exit(-1) ;
    }

    BANNER( log ) ;
    fprintf( log , "Starting the KDC\n"  ) ;
    BANNER( log ) ;

    fprintf( log , "\n<readFrom Amal> FD=%d , <sendTo Amal> FD=%d\n\n" , fd_A2K , fd_K2A );

    // Get Amal's master keys with the KDC and dump it to the log
    myKey_t  Ka ;    // Amal's master key with the KDC

    // Use  getKeyFromFile( "kdc/amalKey.bin" , ....  )
    if ( getKeyFromFile("kdc/amalKey.bin", &Ka) == 0 )
    {	// On failure, print "\nCould not get Amal's Masker key & IV.\n" to both  stderr and the Log file
        // and exit(-1)
        fprintf( stderr , "\nCould not get Amal's Master key & IV.\n" ) ;
        fprintf( log , "\nCould not get Amal's Master key & IV.\n" ) ;
        fclose( log ) ;
        exit(-1) ;
    } else {
        // On success, print "Amal has this Master Ka { key , IV }\n" to the Log file
        fprintf( log, "Amal has this Master Ka { key , IV }\n");
        // BIO_dump the Key IV indented 4 spaces to the righ
        BIO_dump_indent_fp( log, Ka.key, SYMMETRIC_KEY_LEN, 4);
        fprintf( log , "\n" );
        // BIO_dump the IV indented 4 spaces to the righ
        BIO_dump_indent_fp( log, Ka.iv, INITVECTOR_LEN, 4 );
        fprintf( log , "\n" );
    }


    fflush( log ) ;
    
    // Get Basim's master keys with the KDC
    myKey_t   Kb ;    // Basim's master key with the KDC    
    if ( getKeyFromFile("kdc/basimKey.bin", &Kb) == 0 )
    {	// On failure, print "\nCould not get Basim's Masker key & IV.\n" to both  stderr and the Log file
        // and exit(-1)
        fprintf( stderr , "\nCould not get Basim's Master key & IV.\n" ) ;
        fprintf( log , "\nCould not get Basim's Master key & IV.\n" ) ;
        fclose( log ) ;
        exit(-1) ;
    } else {
	    // On success, print "Basim has this Master Kb { key , IV }\n" to the Log file
        fprintf( log, "Basim has this Master Kb { key , IV }\n");
        // BIO_dump the Key IV indented 4 spaces to the righ
        BIO_dump_indent_fp( log, Kb.key, SYMMETRIC_KEY_LEN, 4);
        fprintf( log , "\n" );
        // BIO_dump the IV indented 4 spaces to the righ
        BIO_dump_indent_fp( log, Kb.iv, INITVECTOR_LEN, 4 );
        fprintf( log , "\n" );
    }
    fflush( log ) ;

    //*************************************
    // Receive  & Display   Message 1
    //*************************************
    BANNER( log ) ;
    fprintf( log , "         MSG1 Receive\n");
    BANNER( log ) ;

    char *IDa , *IDb ;
    Nonce_t  Na ;
    
    // Get MSG1 from Amal
    MSG1_receive( log , fd_A2K , &IDa , &IDb , Na ) ;
    //MSG1 ( 49 bytes ) has been received on FD 3 by MSG1_receive():
   // fprintf( log, "MSG1 ( %lu bytes ) has been received on FD %d by MSG1_receive():\n", 
             //sizeof(size_t)*2 + strlen(IDa) + strlen(IDb) + NONCELEN , fd_A2K ) ;

    fprintf( log , "\nKDC received message 1 from Amal with:\n"
                   "    IDa = '%s'\n"
                   "    IDb = '%s'\n" , IDa , IDb ) ;

    fprintf( log , "    Na ( %lu Bytes ) is:\n" , NONCELEN ) ;
     // BIO_dump the nonce Na
    BIO_dump_indent_fp( log, Na , NONCELEN , 4 ) ;
    fprintf( log, "\n" ) ;
    fflush( log ) ;

    
   //*************************************   
    // Construct & Send    Message 2
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG2 New\n");
    BANNER( log ) ;

    myKey_t Ks;
    if( getKeyFromFile("kdc/sessionKey.bin", &Ks) == 0)
    {
        fprintf( stderr , "\nCould not get KDC's Symmetric key & IV.\n" ) ;
        fprintf( log , "\nCould not get KDC's Symmetric key & IV.\n" ) ;
        fclose( log ) ;
        exit(-1) ;
    } else{
        // On success, print "Basim has this Master Kb { key , IV }\n" to the Log file
        fprintf( log, "KDC: created this session key Ks { Key , IV } (%lu Bytes ) is:\n", KEYSIZE);
        // BIO_dump the Key IV indented 4 spaces to the righ
        unsigned char ks_bytes[KEYSIZE];
        memcpy(ks_bytes, Ks.key, SYMMETRIC_KEY_LEN);
        memcpy(ks_bytes + SYMMETRIC_KEY_LEN, Ks.iv, INITVECTOR_LEN);
        BIO_dump_indent_fp(log, (const char *)ks_bytes, KEYSIZE, 4);
        fprintf(log, "\n");

    }

    // make msg2
    uint8_t *msg2 = NULL;
    size_t LenMsg2 = MSG2_new(log, &msg2, &Ka, &Kb, &Ks, IDa, IDb, &Na);
    if (LenMsg2 == 0) {
        fprintf(stderr, "\nKDC failed to make msg2\n");
        fprintf(log,   "\nKDC failed to make msg2\n");
        fclose(log);
        exit(-1);
    }

    // 1) First send the length of MSG2 as a size_t
    size_t off = 0;
    while (off < sizeof(size_t)) {
        ssize_t n = write(fd_K2A, ((uint8_t *)&LenMsg2) + off,
                        sizeof(size_t) - off);
        if (n < 0) {
            perror("KDC write LenMsg2 to Amal");
            fprintf(log, "KDC: Unable to send LenMsg2 to Amal ... EXITING\n");
            fflush(log);
            free(msg2);
            fclose(log);
            exitError("KDC: Unable to send LenMsg2 to Amal");
        }
        off += (size_t)n;
    }

    // 2) Then send the MSG2 ciphertext itself
    off = 0;
    while (off < LenMsg2) {
        ssize_t n = write(fd_K2A, msg2 + off, LenMsg2 - off);
        if (n < 0) {
            perror("KDC write MSG2 to Amal");
            fprintf(log,
                    "KDC: Unable to send all %zu bytes of MSG2 to Amal ... EXITING\n",
                    LenMsg2);
            fflush(log);
            free(msg2);
            fclose(log);
            exitError("KDC: Unable to send all bytes of MSG2 to Amal");
        }
        off += (size_t)n;
    }

    fprintf(log, "The KDC sent the Encrypted MSG2 ( %zu bytes ) to Amal Successfully\n",
            LenMsg2);
    fflush(log);

    free(msg2);
    msg2 = NULL;


    //*************************************   
    // Final Clean-Up
    //*************************************   
end_:
    fprintf( log , "\nThe KDC has terminated normally. Goodbye\n" ) ;
    fclose( log ) ;  
    return 0 ;
}
