#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"
#include "sha256tests.h"



/**
 * Unit tests for the sha256 algorithm  (message padding, preprocessing, working variables, hash functions, hash computation)
 * Some tests use examples from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
 */


/**
 * Prints all functions starting with 'void test' of the importing file. 
 * Can be used to update a function that calls all the test cases.
 */
#define PRINT_TEST_FUNCTIONS  \
     char command[] = "cat " __FILE__ " | grep '^void test' | sed -e 's/void//' -e 's/{/;/'"; \
     FILE *f = popen(command, "w"); \
     pclose(f); 

/**
 * Tests two strings for equality.
 */
#define TEST_STRING_EQUALS(expected, actual) \
	if(strcmp(expected, actual) != 0){ \
		printf("%s, line %d: Expected %s, but was %s\n", __FUNCTION__, __LINE__, expected, actual); \
		failed_tests += 1; \
	}else{ \
		passed_tests += 1; \
	}

/**
 * Tests two integers for equality.
 */
#define TEST_INT_EQUALS(expected, actual) \
	if(expected != actual){ \
		printf("%s, line %d: Expected %d (0x%llx), but was %d (0x%llx)\n", __FUNCTION__, __LINE__, expected, expected, actual, actual); \
		failed_tests += 1; \
	}else{ \
		passed_tests += 1; \
	}
/**
 * Within a loop: Tests two integers for equality.
 */
#define TEST_INT_EQUALS_LOOP(i, expected, actual) \
	if(expected != actual){ \
		printf("%s, line %d, Index %d: Expected %d (0x%llx), but was %d (0x%llx)\n", __FUNCTION__, __LINE__, i, expected, expected, actual, actual); \
		failed_tests += 1; \
	}else{ \
		passed_tests += 1; \
	}

/**
 * Tests two long long integers for equality.
 */
#define TEST_LONGLONG_EQUALS(expected, actual) \
	if(expected != actual){ \
		printf("%s, line %d: Expected 0x%llx, but was 0x%llx\n", __FUNCTION__, __LINE__, expected, actual); \
		failed_tests += 1; \
	}else{ \
		passed_tests += 1; \
	}
	
	

/**
 * Last command in the function that calls the test functions.
 * Prints the results.
 */
#define PRINT_TEST_RESULTS \
	printf("\nResults of testing %s: \nPassed tests: %lld\nFailed tests: %lld\n", __FILE__, passed_tests, failed_tests); \
    passed_tests = 0; \
    failed_tests = 0;
   

  volatile int passed_tests = 0; 
  volatile int failed_tests = 0;

/**
 * Test vectors from: https://di-mgt.com.au/sha_testvectors.html
 */

void test_sha256_message_with_0_bits(){
     int message[] = {};
     long long int message_length = 0;
      int expected[] = {0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855};
      int actual[]={0,0,0,0,0,0,0,0}; //Hash buffer
     sha256(message, message_length, actual) ;
     for(int i = 0; i < 8; i++){
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }
}

void test_sha256_message_with_24_bits(){
  //"abc"
     int message[] = {0x61626300};
      long long int message_length = 24;
      int expected[] = {0xBA7816BF, 0x8F01CFEA, 0x414140DE, 0x5DAE2223, 0xB00361A3, 0x96177A9C, 0xB410FF61, 0xF20015AD};
      int actual[]={0,0,0,0,0,0,0,0}; //Hash buffer
     sha256(message, message_length, actual) ;
     for(int i = 0; i < 8; i++){
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }
}

void test_sha256_message_with_1176_bits(){
// "Im Anfang erschuf Gott Himmel und Erde. Die Erde war wuest und wirr und Finsternis lag ueber der Urflut und Gottes Geist schwebte ueber dem Wasser." 
  int message[] = \
 {0x496d2041 ,0x6e66616e ,0x67206572 ,0x73636875 ,0x6620476f ,0x74742048 ,0x696d6d65 ,0x6c20756e , \
  0x64204572 ,0x64652e20 ,0x44696520 ,0x45726465 ,0x20776172 ,0x20777565 ,0x73742075 ,0x6e642077 , \
  0x69727220 ,0x756e6420 ,0x46696e73 ,0x7465726e ,0x6973206c ,0x61672075 ,0x65626572 ,0x20646572 , \
  0x20557266 ,0x6c757420 ,0x756e6420 ,0x476f7474 ,0x65732047 ,0x65697374 ,0x20736368 ,0x77656274 , \
  0x65207565 ,0x62657220 ,0x64656d20 ,0x57617373 ,0x65722e00}; 
  
     long long int message_length = 1176;
     int expected[] = {0x62c890f9 ,0xbb0f1bb7 ,0xd03ee3d4 ,0xb0f1428f ,0xa592edc0 ,0x14f60f80 ,0x2b2bb827 ,0x0c34d0d5};
     int actual[]={0,0,0,0,0,0,0,0}; //Hash buffer
     sha256(message, message_length, actual) ;
     for(int i = 0; i < 8; i++){
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }
}



void test_sha256_message_with_448_bits(){
// "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" 
     int message[] = {0x61626364, 0x62636465, 0x63646566, 0x64656667, 0x65666768, 0x66676869, 0x6768696A, 0x68696A6B, 0x696A6B6C, 0x6A6B6C6D, 0x6B6C6D6E, 0x6C6D6E6F, 0x6D6E6F70, 0x6E6F7071}; 
     long long int message_length = 448;
     int expected[] = {0x248D6A61, 0xD20638B8, 0xE5C02693, 0x0C3E6039, 0xA33CE459, 0x64FF2167, 0xF6ECEDD4, 0x19DB06C1};
     int actual[]={0,0,0,0,0,0,0,0}; //Hash buffer
     sha256(message, message_length, actual) ;
     for(int i = 0; i < 8; i++){
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }
}

void test_sha256_message_with_8_Million_bits(){
//Testvector from https://di-mgt.com.au/sha_testvectors.html - Message is 1 Million times the character 'a' (dec 97, hex 61)
     int oneM = 1000000; //bytes 
     long long int message_length = 8000000; //bits
     int words = 250000;// message_length / 32;
     int message[words];
     for(int i = 0; i < words; i++){
          message[i] = 0x61616161;
     }
     int expected[] = {0xcdc76e5c,0x9914fb92,0x81a1c7e2,0x84d73e67,0xf1809a48,0xa497200e,0x046d39cc,0xc7112cd0};
     int actual[]={0,0,0,0,0,0,0,0};  
     sha256(message, message_length, actual) ;
     for(int i = 0; i < 8; i++){
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }
}
	

void test_Sigma1_1(){
      int input = 1;
      int expected = 0x4200080;
      int actual = test_Sigma1(input);
     TEST_INT_EQUALS(expected, actual)
}

void test_Sigma1_2(){
      int input = 0xcafebabe;
      int expected = 0xd3affa58;
      int actual = test_Sigma1(input);
     TEST_INT_EQUALS(expected, actual)
}	

void test_Sigma0_1(){
      int input = 1;
      int expected = 0x40080400;
      int actual = test_Sigma0(input);
     TEST_INT_EQUALS(expected, actual)
}

void test_Sigma0_2(){
      int input = 0xcafebabe;
      int expected = 0x9da30271;
      int actual = test_Sigma0(input);
     TEST_INT_EQUALS(expected, actual)
}

void test_sig0_1(){
      int input = 8;
      int expected = 0x10020001;
      int actual = test_sig0(input);
     TEST_INT_EQUALS(expected, actual)
}

void test_sig0_2(){
      int input = 2;
      int expected = 0x4008000;
      int actual = test_sig0(input);
     TEST_INT_EQUALS(expected, actual)
}


void test_sig1_1(){
      int input = 2048;
      int expected = 0x5000002;
      int actual = test_sig1(input);
     TEST_INT_EQUALS(expected, actual)
}

void test_sig1_2(){
      int input = 15;
      int expected = 0x66000;
      int actual = test_sig1(input);
     TEST_INT_EQUALS(expected, actual)
}



void test_Ch_1(){
      int x = 1;
      int y = 3;
      int z = 4;
      int expected = 5;
      int actual = test_Ch(x, y, z);
     TEST_INT_EQUALS(expected, actual)
}

void test_Ch_2(){
      int x = 0xcafeb1b1;
      int y = 0xd0d0d1d0;
      int z = 0xdeaf1234;
      int expected = 0xd4d19394;
      int actual = test_Ch(x, y, z);
     TEST_INT_EQUALS(expected, actual)
}

void test_Ch_3(){
      int x = 0xcafebabe;
      int y = 0xd0d0d1d0;
      int z = 0xdeaf1234;
      int expected = 0xd4d19090;
      int actual = test_Ch(x, y, z);
     TEST_INT_EQUALS(expected, actual)
}

void test_Maj_1(){
      int x = 0xcafebabe;
      int y = 0xd0d0dead;
      int z = 0xf1faabba; 
      int expected = 0xd0fababe;
      int actual = test_Maj(x, y, z);
     TEST_INT_EQUALS(expected, actual)
}

/**
 *  T1 = h          + Sigma1(e)          + Ch(e,f,g)                            + K          + W
 *  T1 = 0x12345678 + Sigma1(0xcafebabe) + Ch(0xcafebabe,0xd0d0d1d0,0xdeaf1234) + 0x428a2f98 + 0xf00badad 
 *  T1 = 0x12345678 +    0xd3affa58      +           0xd4d19090                 + 0x428a2f98 + 0xf00badad  
 *  T1 = 0xed4bbea5     
 */
void test_set_t1_1(){
      int h = 0x12345678;
      int e = 0xcafebabe;
      int f = 0xd0d0d1d0;
      int g = 0xdeaf1234;
      int k = 0x428a2f98;
      int w = 0xf00badad;
      int expected = 0xed4bbea5;
      int actual = test_setT1(h,e,f,g,k,w);
     TEST_INT_EQUALS(expected, actual)
}

/**
 *  T1 = h          + Sigma1(e)          + Ch(e,f,g)                            + K          + W
 *  with overflow:
 *  T1 = 0xffffffff + Sigma1(0xcafebabe) + Ch(0xcafebabe,0xd0d0d1d0,0xdeaf1234) + 0xffffffff + 0xffffffff 
 *  T1 = 0xffffffff +    0xd3affa58      +           0xd4d19090                 + 0xffffffff + 0xffffffff  
 *  T1 = 0xa8818ae5   (= 0x4a8818ae5 modulo 2^32)
 */
void test_set_t1_2(){
      int h = 0xffffffff;
      int e = 0xcafebabe;
      int f = 0xd0d0d1d0;
      int g = 0xdeaf1234;
      int k = 0xffffffff;
      int w = 0xffffffff;
      int expected = 0xa8818ae5;
      int actual = test_setT1(h,e,f,g,k,w);
     TEST_INT_EQUALS(expected, actual)
}

void test_set_t2_1(){
      int a = 0xcafebabe;
      int b = 0xd0d0dead;
      int c = 0xf1faabba;
      int expected = 0x6e9dbd2f;
      int actual = test_setT2(a,b,c);
     TEST_INT_EQUALS(expected, actual)
}

void test_prepare_first_16_schedules(){
      int block[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
      int expected[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
      int actual[]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};  
     prepare_first_16_schedules(block, actual) ;
     for(int i = 0; i < 16; i++){
	//  printf("%d: %x %x\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }     
}

void test_calculate_values_from_messagelength_1(){
       int actual[]={0,0,0,0,0};
       int messagelength = 1024;//2 Blocks, no free space
       int expected[] = {2, 0, 0,0,0};//blocks, blockremainder, words, wordremainder, freespace
     calculate_values_from_messagelength(actual, messagelength); 
     for(int i = 0; i < 5; i++){
     //     printf("%d:exp %d actual %d\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}

void test_calculate_values_from_messagelength_2(){
       int actual[]={0,0,0,0,0};
       int messagelength = 1025;//2 Blocks, 1 residual bit,  no words, enough free space for padding
       int expected[] = {2, 1, 0,1,1};//blocks, blockremainder, words, wordremainder, freespace
     calculate_values_from_messagelength(actual, messagelength); 
     for(int i = 0; i < 5; i++){
     //     printf("%d:exp %d actual %d\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}


void test_calculate_values_from_messagelength_3(){
       int actual[]={0,0,0,0,0};
       int messagelength = 100001;//contains 195 blocks (99840 bits), blockremainder 161 bits,  5 words (5x32=160 bits), 1 residual bits, enough freespace for padding
       int expected[] = {195, 161, 5, 1, 1};//blocks, blockremainder, words, wordremainder, freespace
     calculate_values_from_messagelength(actual, messagelength); 
     for(int i = 0; i < 5; i++){
     //     printf("%d:exp %d actual %d\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}

void test_calculate_values_from_messagelength_4(){
       int actual[]={0,0,0,0,0};
       int messagelength = 447; //freespace 65 bits
        int expected[] = {0, 447, 13, 31, 1};//blocks, blockremainder, words, wordremainder, freespace
     calculate_values_from_messagelength(actual, messagelength); 
     for(int i = 0; i < 5; i++){
       //  printf("%d:exp %d actual %d\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}

void test_calculate_values_from_messagelength_5(){
       int actual[]={0,0,0,0,0};
       int messagelength = 448; //freespace only 64 bits
        int expected[] = {0, 448, 14, 0, 2};//blocks, blockremainder, words, wordremainder, freespace
     calculate_values_from_messagelength(actual, messagelength); 
     for(int i = 0; i < 5; i++){
       //  printf("%d:exp %d actual %d\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}

void test_calculate_values_from_messagelength_6(){
       int actual[]={0,0,0,0,0};
       int messagelength = 490; 
        int expected[] = {0, 490, 15, 10, 2};//blocks, blockremainder, words, wordremainder, freespace
     calculate_values_from_messagelength(actual, messagelength); 
     for(int i = 0; i < 5; i++){
       //  printf("%d:exp %d actual %d\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}

void test_calculate_values_from_messagelength_7(){
       int actual[]={0,0,0,0,0};
       int messagelength = 511; //1 free bit for padding, length in new block
        int expected[] = {0, 511, 15, 31, 2};//blocks, blockremainder, words, wordremainder, freespace
     calculate_values_from_messagelength(actual, messagelength); 
     for(int i = 0; i < 5; i++){
       //  printf("%d:exp %d actual %d\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}

void test_calculate_values_from_messagelength_8(){
       int actual[]={0,0,0,0,0};
       int messagelength = 0; 
        int expected[] = {0, 0, 0, 0, 0};//blocks, blockremainder, words, wordremainder, freespace
     calculate_values_from_messagelength(actual, messagelength); 
     for(int i = 0; i < 5; i++){
       //  printf("%d:exp %d actual %d\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}


void test_clear_schedules(){
       int actual[64] =   {1,2,3,4,5,6,7,8, 9,10,11,12,13,14,15,16, 17,18,19,20,21,22,23,24, 25,26,27,28,29,30,31,32, 33,34,35,36,37,38,39,40, 41,42,43,44,45,46,47,48, 49,50,51,52,53,54,55,56, 57,58,59,60,61,62,63,64};
       int expected[64] = {0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
     clear_schedules(actual); 
     for(int i = 0; i<64; i++){
         // printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}

void test_prepare_17th_schedule(){
       int values[16] = {1,2,3,4,5,6,7,8, 9,10,11,12,13,14,15,16}; 
       int actual[17] = {0xfe,0xfa,0xba,0xbe,0xd0,0xde,0xe1,0xd1,0xca,0xfe,0xa1,0xd1,0xf0,0xd0,0x1d,0xab,0xba};
       int expected[17] = {1,2,3,4,5,6,7,8, 9,10,11,12,13,14,15,16, 0x406e00b};
      int value17 = prepare_17th_schedule(values, actual);
     //printf("exp %x actual %x\n", 0x406e00b, value17);
     TEST_INT_EQUALS(0x406e00b, value17)
     for(int i = 0; i<17; i++){
       // printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
          TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
     }      
}




void test_set_working_variables_1(){
      int firstWorkingSchedule = 0x61626380; //"abc"    
     //variables after first round
       int expected[] = {0x5d6aebcd, 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xfa2a4622, 0x510e527f, 0x9b05688c, 0x1f83d9ab};
       int actual[] = {0,0,0,0,0,0,0,0}; 
     set_working_variables_once(firstWorkingSchedule, actual); 
          for(int i = 0; i<8; i++){
	 // printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	  TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

void test_set_working_variables_2(){
      int firstWorkingSchedule = 0x61626364; //"abcd"    
     //variables after first round
       int expected[] = {0x5d6aebb1, 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xfa2a4606, 0x510e527f, 0x9b05688c, 0x1f83d9ab};
       int actual[] = {0,0,0,0,0,0,0,0}; 
     set_working_variables_once(firstWorkingSchedule, actual); 
          for(int i = 0; i<8; i++){
	//  printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	  TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

void test_set_working_variables_16times_1(){
     //variables after 16 rounds (t=15)
       int expected[] = {0xb0fa238e, 0xc0645fde, 0xd932eb16, 0x87912990, 0x07590dcd, 0x0B92f20c, 0x745a48de, 0x1e578218};
       int schedule[] = {0x61626380,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x00000018}; //padded block for message "abc"
       int actual[] = {0,0,0,0,0,0,0,0}; 
     set_working_variables_16_times(schedule, actual); 
          for(int i = 0; i<8; i++){
	 // printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	  TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}



void test_set_working_variables_16times_2(){
     //variables after 16 rounds (t=15)
       int expected[] = {0xc3486194, 0xdd16cbb3, 0xd68e6457, 0x101a4861, 0x1496a54f, 0x9162aded, 0x9243f8af, 0x839a0fc9};
       int schedule[] = {0x61626364,0x62636465,0x63646566,0x64656667,0x65666768,0x66676869,0x6768696a,0x68696a6b,0x696a6b6c,0x6a6b6c6d,0x6b6c6d6e,0x6c6d6e6f,0x6d6e6f70,0x6e6f7071,0x80000000,0}; 
                                //first padded block of message "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
       int actual[] = {0,0,0,0,0,0,0,0}; 
     set_working_variables_16_times(schedule, actual); 
          for(int i = 0; i<8; i++){
	 // printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	  TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

void test_set_working_variables_64times(){
     //variables after 64 rounds (t=63)
       int expected[] = {0x1BDC6F6F, 0x86126910, 0xF6F443F8, 0xBCFCE922, 0x25D2430A, 0x2FC08F85, 0xACC75916, 0x962D8621};
     //first block of message "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
       int schedule[] = {0x61626364,0x62636465,0x63646566,0x64656667,0x65666768,0x66676869,0x6768696a,0x68696a6b,0x696a6b6c,0x6a6b6c6d,0x6b6c6d6e,0x6c6d6e6f,0x6d6e6f70,0x6e6f7071,0x80000000,0}; 
                                
       int actual[] = {0,0,0,0,0,0,0,0}; 
     set_working_variables_64_times(schedule, actual); 
          for(int i = 0; i<8; i++){
	//  printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	  TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

void test_compute_intermediate_hash_value(){
       int expected[] = {0x85E655D6, 0x417A1795, 0x3363376A, 0x624CDE5C, 0x76E09589, 0xCAC5F811, 0xCC4B32C1, 0xF20E533A};
     //first block of message "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
       int schedule[] = {0x61626364,0x62636465,0x63646566,0x64656667,0x65666768,0x66676869,0x6768696a,0x68696a6b,0x696a6b6c,0x6a6b6c6d,0x6b6c6d6e,0x6c6d6e6f,0x6d6e6f70,0x6e6f7071,0x80000000,0}; 
       int actual[] = {0,0,0,0,0,0,0,0}; 
     compute_intermediate_hash_value(schedule, actual);
          for(int i = 0; i<8; i++){
         //   printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }

}

void test_compute_intermediate_hash_value_2(){
       int expected[] = {0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad};
     //message "abc", padded first block:
       int schedule[] = {0x61626380,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x00000018}; 
       int actual[] = {0,0,0,0,0,0,0,0}; 
     compute_intermediate_hash_value(schedule, actual);
          for(int i = 0; i<8; i++){
         //   printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }

}

void test_compute_intermediate_hash_value_3(){ //e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855
       int expected[] = {0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855};
     //empty message "", padded first and only block:
       int schedule[] = {0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; 
       int actual[] = {0,0,0,0,0,0,0,0}; 
     compute_intermediate_hash_value(schedule, actual);
          for(int i = 0; i<8; i++){
         //   printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }

}


void test_set_residual_bits_1(){
       //             | full block = 16 words = 512 bits    | 
       int message[] ={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
       long long int messagelength = 512;
       int expected[] = {0x80000000,0,0,0,0,0,0,0,0,0,0,0,0,0,0,512,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
       int actual[] =  {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
     set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
         //   printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

void test_set_residual_bits_2(){
        
       int message[] ={};
       long long int messagelength = 0;
       int expected[] = {0x80000000,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
       int actual[] =  {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
       set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
        //   printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	    TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}



void test_set_residual_bits_3(){
       //             | no full block, only 15 words = 480 bits   -> 2. additional block needed 
       int message[] ={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
       long long int messagelength = 480;
       int expected[] = {1,2,3,4,5,6,7,8, 9,10,11,12,13,14,15,0x80000000, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,480};
       int actual[] =   {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
     set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
         //   printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

void test_set_residual_bits_4(){
       //             |  full block, 16 words = 512 bits     | 3 bytes rest = 24 bits
       long long int messagelength = 536;
       int expected[] = {0xcafeba80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,536,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
       int actual[] =   {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
       int message[] ={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,0xcafeba00};
     set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
         //   printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

void test_set_residual_bits_5(){
       //             |  full block, 16 words = 512 bits     | 1 word = 32 bits, 3 bytes  = 24 bits, nibble and 1 bit = 5 bits
       int message[] ={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,0xcafebabe,0xffeedde8};//e8 in bin: 1110 1000 with 1: 1110 1100
       long long int messagelength = 573;
       int expected[] = {0xcafebabe,0xffeeddec,0,0,0,0,0,0,0,0,0,0,0,0,0,573,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
       int actual[] =   {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
     set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
         //   printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

void test_set_residual_bits_6(){
       //             |  full block, 16 words = 512 bits     | 2 words = 64 bits, //padding 1 with 0x80000000
       int message[] ={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,0xcafebabe,0xffeeddcc}; 
       long long int messagelength = 576;
       int expected[] = {0xcafebabe,0xffeeddcc,0x80000000,0,0,0,0,0,0,0,0,0,0,0,0,576,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
       int actual[] =   {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
     set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
         //   printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

void test_set_residual_bits_7(){
       //             |1 word (32), 3 bytes (24), 1 nibble c (4), (2) bits 0xc = b1100 padding with 1: b1110 = 0xe
       int message[] ={0xcafebabe,0xffeeddcc}; 
       long long int messagelength = 62;
       int expected[] = {0xcafebabe,0xffeeddce,0,0,0,0,0,0, 0,0,0,0,0,0,0,62, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
       int actual[] =   {0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
     set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
      //  printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

void test_set_residual_bits_8(){
       // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" 
       int message[] = {0x61626364, 0x62636465, 0x63646566, 0x64656667, 0x65666768, 0x66676869, 0x6768696A, 0x68696A6B, 0x696A6B6C, 0x6A6B6C6D, 0x6B6C6D6E, 0x6C6D6E6F, 0x6D6E6F70, 0x6E6F7071}; 
       long long int messagelength = 448;
       int expected[] = {0x61626364, 0x62636465, 0x63646566, 0x64656667, 0x65666768, 0x66676869, 0x6768696A, 0x68696A6B, 0x696A6B6C, 0x6A6B6C6D, 0x6B6C6D6E, 0x6C6D6E6F, 0x6D6E6F70, 0x6E6F7071,0x80000000, 0,  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x1c0 }; 

       int actual[] =   {0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
       set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
    //    printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

void test_set_residual_bits_9(){
       int message[] = {0x65207565 ,0x62657220 ,0x64656d20 ,0x57617373 ,0x65722e00}; 
       long long int messagelength = 152;
       int expected[] = {0x65207565 ,0x62657220 ,0x64656d20 ,0x57617373 ,0x65722e80, 0,0,0,0,0,0,0,0,0,0,0x98, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0}; 

       int actual[] =   {0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
       set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
    //    printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

void test_set_residual_bits_10(){
  int message[] = \
 {0x496d2041 ,0x6e66616e ,0x67206572 ,0x73636875 ,0x6620476f ,0x74742048 ,0x696d6d65 ,0x6c20756e , \
  0x64204572 ,0x64652e20 ,0x44696520 ,0x45726465 ,0x20776172 ,0x20777565 ,0x73742075 ,0x6e642077 , \
  0x69727220 ,0x756e6420 ,0x46696e73 ,0x7465726e ,0x6973206c ,0x61672075 ,0x65626572 ,0x20646572 , \
  0x20557266 ,0x6c757420 ,0x756e6420 ,0x476f7474 ,0x65732047 ,0x65697374 ,0x20736368 ,0x77656274 , \
  0x65207565 ,0x62657220 ,0x64656d20 ,0x57617373 ,0x65722e00}; 
  
     long long int message_length = 1176;
       int expected[] = {0x65207565 ,0x62657220 ,0x64656d20 ,0x57617373 ,0x65722e80, 0,0,0,0,0,0,0,0,0,0,0x498, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0}; 
       long long messagelength = 1176;
       int actual[] =   {0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
       set_residual_bits(message,messagelength,actual);
         for(int i = 0; i<32; i++){
    //    printf("%d:exp %x actual %x\n", i, expected[i], actual[i]);
	      TEST_INT_EQUALS_LOOP(i,expected[i], actual[i])    
          }
}

int main(void){
/**
 *  To print a list of all test functions, uncomment
 */
//PRINT_TEST_FUNCTIONS

 printf("\nTesting SHA-256 functions.\n");

 test_sha256_message_with_0_bits();
 test_sha256_message_with_24_bits();
 test_sha256_message_with_1176_bits();
 test_sha256_message_with_448_bits();
 test_sha256_message_with_8_Million_bits();
 test_Sigma1_1();
 test_Sigma1_2();
 test_Sigma0_1();
 test_Sigma0_2();
 test_sig0_1();
 test_sig0_2();
 test_sig1_1();
 test_sig1_2();
 test_Ch_1();
 test_Ch_2();
 test_Ch_3();
 test_Maj_1();
 test_set_t1_1();
 test_set_t1_2();
 test_set_t2_1();
 test_prepare_first_16_schedules();
 test_calculate_values_from_messagelength_1();
 test_calculate_values_from_messagelength_2();
 test_calculate_values_from_messagelength_3();
 test_calculate_values_from_messagelength_4();
 test_calculate_values_from_messagelength_5();
 test_calculate_values_from_messagelength_6();
 test_calculate_values_from_messagelength_7();
 test_calculate_values_from_messagelength_8();
 test_clear_schedules();
 test_prepare_17th_schedule();
 test_set_working_variables_1();
 test_set_working_variables_2();
 test_set_working_variables_16times_1();
 test_set_working_variables_16times_2();
 test_set_working_variables_64times();
 test_compute_intermediate_hash_value();
 test_compute_intermediate_hash_value_2();
 test_compute_intermediate_hash_value_3();  
 test_set_residual_bits_1();
 test_set_residual_bits_2();
 test_set_residual_bits_3();
 test_set_residual_bits_4();
 test_set_residual_bits_5();
 test_set_residual_bits_6();
 test_set_residual_bits_7();
 test_set_residual_bits_8();
 test_set_residual_bits_9();
 test_set_residual_bits_10();


   PRINT_TEST_RESULTS
}
