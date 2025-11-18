/*----------------------------------------------------------------------------
pa-04_PartTwo:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   amal.c     SKELETON

Written By: 
     1- YOU  MUST   WRITE 
	 2- FULL NAMES  HERE   (or risk losing points )
Submitted on: 
     Insert the date of Submission here
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
    
    
    
    //*************************************
    // Receive   &   Process Message 2
    //*************************************
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG2 Receive\n");
    BANNER( log ) ;

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

