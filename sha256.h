
/**
 * Implementation of the SHA-256 algorithm in ARM-64 bit assembly.
 * 
 * message: 
 * message_length: length in bits (max 2^64 -1 bits)
 * hash: pointer to an array of eight u32 integers
 */
void sha256(int *message, long long int message_length_in_bits, int *hash);






