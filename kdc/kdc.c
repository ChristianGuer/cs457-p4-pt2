/*----------------------------------------------------------------------------
pa-04_PartTwo:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   kdc.c    SKELETON

Written By: 
     1- YOU  MUST   WRITE 
	 2- FULL NAMES  HERE   (or risk losing points )
Submitted on: 
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
    
    
    

    //*************************************   
    // Construct & Send    Message 2
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG2 New\n");
    BANNER( log ) ;


    //*************************************   
    // Final Clean-Up
    //*************************************   
end_:
    fprintf( log , "\nThe KDC has terminated normally. Goodbye\n" ) ;
    fclose( log ) ;  
    return 0 ;
}
