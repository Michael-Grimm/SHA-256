
/**
 * Implementation of the SHA-256 algorithm in ARM-64 bit assembly.
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 * message: pointer to an array of u32 integers
 * message_length: length in bits (max 2^64 -1 bits)
 * hash: final hash value, pointer to an array of eight u32 integers
 */
void sha256(int *message, long long int message_length_in_bits, int *hash);






