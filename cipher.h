/**
 * @brief Encodes the given text into the buffer given (encrypted_text)
 *
 * @param plaintext Text to encode
 * @param encrypted_text Output to where this function should set bits
 * @param num_bits_used Value to assign how many bits were written
 */
void encode( char const * plaintext, char* encryptedtext, int *num_bits_used );

void decode( char const* ciphertext, int num_chars, char* plaintext );

/* helper function for debugging */
void print_bits(const char* buffer, int start_pos, int how_many );
