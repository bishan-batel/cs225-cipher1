#include "cipher.h"
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef char byte;

/* may be useful for debugging */
void print_bit(char v, int pos) {
  char one = 1;
  if (v & one << pos) {
    printf("1");
  } else {
    printf("0");
  }
}

/* may be useful for debugging */
void print_bits(char *buffer, int start_pos, int how_many) {
  int i, j;
  printf("Bits: ");
  for (i = 0; i < how_many;) { /* for each char */
    const char *ch = buffer + (start_pos + i) / 8;
    for (j = 0; j < 8 && i < how_many; ++j, ++i) { /* from more significant to less */
      print_bit(*ch, j);
    }
  }
  printf("\n");
}

int read_bit(char const *buffer, int i) {
  char const *ch = buffer + i / 8;
  int pos = i % 8;
  return (*ch & 1 << pos) ? 1 : 0;
}

/* decode num_chars characters from ciphertext */
/* function assumes output C-style string is allocated by someone else and big enough */
void decode(char const *ciphertext, int num_chars, char *plaintext) {
  int i, j;
  int pos = 0;
  for (i = 0; i < num_chars; ++i) {
    /* read 2 bits for group (00,01,10,11) */
    int group_index = read_bit(ciphertext, pos) + 2 * read_bit(ciphertext, pos + 1);
    int index = 0; /* index inside group */
    pos += 2;
    for (j = 0; j < group_index + 1; ++j) {
      index += (read_bit(ciphertext, pos) << j);
      ++pos;
    }
    plaintext[i] = 'a' + ((1 << (group_index + 1)) - 2) + index;
  }
  plaintext[num_chars] = 0; /* null terminate final result */
}

/**
 * @brief Gets the bit in the given byte from a given bit index
 *
 * @param b Byte to read from
 * @param bit_index Index of the bit to read in little-endian
 * @return
 */
bool get_bit(const byte b, const size_t bit_index) { return (b >> bit_index) & 0x1; }

/**
 * @brief Sets the bit in the given byte array at position (bit_position)
 *
 * @param output Output to write to
 * @param bit_position Bit position (left to right)
 * @param c Bit value to set
 */
void set_bit(byte *output, const size_t bit_position, const bool c) {
  /* get the byte index that contains the specified bit*/
  const size_t byte_index = bit_position / 8;
  const size_t bit_index = bit_position - byte_index * 8;

  /* mask out the bit we are going to write to*/
  const byte masked_value = output[byte_index] & ~(1 << bit_index);

  /* set the bit to 'c' */
  const byte updated_value = masked_value | (c << bit_index);

  /* update the byte index */
  output[byte_index] = updated_value;
}

/**
 * @brief Gets the cipher char group for the input char
 *
 * @param c Char to convert
 */
byte get_char_cipher_group(const char c) {
  const char index = c - 'a';
  if (index < 2) return 0;
  if (index < 6) return 1;
  if (index < 14) return 2;
  return 3;
}

/**
 * @brief Encodes a single char into a output stream
 *
 * @param output_encrypted The stream to write to
 * @param c Character to encode
 * @param bit_position The bit position to start writing
 * @return How many bytes were written
 */
size_t encode_char(byte *const output_encrypted, const char c, size_t bit_position) {
  static const byte GROUP_OFFSETS[4] = {0, 2, 6, 14};

  const byte group = get_char_cipher_group(c);
  const byte group_index = (c - 'a') - GROUP_OFFSETS[(size_t) group];

  byte i = 0; /* volper please why do you make these assignments in ANSI-C */

  /* write the group bits (2) */
  set_bit(output_encrypted, bit_position++, get_bit(group, 0));
  set_bit(output_encrypted, bit_position++, get_bit(group, 1));

  for (; i <= group; i++) {
    set_bit(output_encrypted, bit_position++, get_bit(group_index, i));
  }

  return 3 + group;
}

void encode(const char *plaintext, byte *const encrypted_text, int *const num_bits_used) {
  size_t bit_position = 0;

  for (; *plaintext; plaintext++) {
    bit_position += encode_char(encrypted_text, *plaintext, bit_position);
  }

  *num_bits_used = (int) bit_position;
}
