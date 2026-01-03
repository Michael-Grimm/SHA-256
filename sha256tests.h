/**
 *  Tests functions for 4.1.2 SHA-256 functions.
 */
 int test_Sigma0( int);
 int test_Sigma1( int);
 int test_sig0( int);
 int test_sig1( int);
 int test_Ch( int x,  int y,  int z);
 int test_Maj( int x,  int y,  int z);
 int  test_setT1( int h,  int e,  int f,  int g,  int k,  int w);
 int  test_setT2( int a,  int b,  int c);
void prepare_first_16_schedules( int *block,  int *workingschedule);
void calculate_values_from_messagelength(  int *actual,   int messagelength); 
void clear_schedules(  int *values);
 int prepare_17th_schedule(  int *values,   int *actual); 
void prepare_schedule(  int *values,   int *actual);
void set_working_variables_once( int firstWorkingschedule,   int *actual);
void set_working_variables_16_times(  int *schedule,   int *actual);
void set_working_variables_64_times(  int *schedule,   int *actual);
void compute_intermediate_hash_value(  int *schedule,   int *actual);
void set_residual_bits(int *message, long long int messagelength,   int *residualbits);
