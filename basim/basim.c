/*----------------------------------------------------------------------------
pa-04_PartTwo:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   basim.c     SKELETON

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

// Generate random nonces for Basim
void  getNonce4Basim( int which , Nonce_t  value )
{
	// Normally we generate random nonces using
	// RAND_bytes( (unsigned char *) value , NONCELEN  );
	// However, for grading purpose, we will use fixed values

	switch ( which ) 
	{
		case 1:		// the first and Only nonce
			value[0] = 0x66778899 ;
			break ;

		default:	// Invalid agrument. Must be either 1 or 2
			fprintf( stderr , "\n\nBasim trying to create an Invalid nonce\n exiting\n\n");
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
    // Receive  & Process   Message 3
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG3 Receive\n");
    BANNER( log ) ;

    //*************************************
    // Construct & Send    Message 4
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG4 New\n");
    BANNER( log ) ;

    //*************************************
    // Receive   & Process Message 5
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG5 Receive\n");
    BANNER( log ) ;

    //*************************************   
    // Final Clean-Up
    //*************************************
end_:
    fprintf( log , "\nBasim has terminated normally. Goodbye\n" ) ;
    fclose( log ) ;  

    return 0 ;
}
