import json
 
class AES:
    
    with open('constants.json') as json_file:
        CONSTANT = json.load(json_file)

    def __init__(self, security_parameter, master_key):
        self.security_parameter = int(security_parameter)
        self.master_key = master_key
        
        if len(self.master_key) != self.security_parameter or (self.security_parameter not in [int(i)*8 for i in AES.CONSTANT["NO_OF_ROUNDS"]]):
            raise ValueError("This implementation of AES supports 128, 192 and 256 as security parameter (l) with key size as 128, 192 and 256 bits respectively.")

        no_of_bytes = str(int(len(self.master_key)/8))

        self.master_key = int(self.master_key, 2)

        self.no_of_rounds = AES.CONSTANT["NO_OF_ROUNDS"][no_of_bytes]
        self.no_of_words = AES.CONSTANT["NO_OF_WORDS"][no_of_bytes]
        
        self.master_key = self.master_key.to_bytes(int(self.security_parameter/8), 'big')
        self.round_keys = self.generateRoundKeys()
        
    def helper__sub_byte(self, b, s_box):
        b = hex(b)[2:]
        if len(b) == 1: b = '0' + b
        r, c = list(b)
        return int(s_box[8*int(r, 16) + int(c, 16)], 16)

    def helper_sub_bytes(self, rows, s_box):
        mat = []
        for row in rows:
            new_row = []
            for j in row:
                new_row.append(self.helper__sub_byte(j, s_box))
            mat.append(new_row)
        return mat

    def helper_g(self, word, rc):
        word = [self.helper__sub_byte(b, self.CONSTANT["S_BOX"]) for b in word[1:] + [word[0]]]
        return [word[0] ^ rc] + word[1:]

    def generateRoundKeys(self):
        r_keys = []
        for word in range(self.no_of_words):
            r_keys.append([self.master_key[4 * word], self.master_key[4 * word + 1], self.master_key[4 * word + 2], self.master_key[4 * word + 3]])

        for word in range(self.no_of_words, (4 * (self.no_of_rounds + 1))):
            tmp = r_keys[word - 1]
            if word % self.no_of_words == 0:
                tmp = self.helper_g(tmp, int(self.CONSTANT["RCON"][int(word / self.no_of_words)], 16))
            elif self.no_of_words > 6 and word % self.no_of_words == 4:
                tmp = self.helper_sub_bytes([tmp], self.CONSTANT["S_BOX"])[0]
            r_keys.append([x ^ y for x, y in zip(r_keys[word - self.no_of_words], tmp)])
        return r_keys
        
    def getByteFromHex(self, word, row, hex_data):
        return 0xFF & (hex_data>>(8*(16-(4*word+row)-1)))

    def hexTo4x4Matrix(self, hex_data):
        matrix4x4 = []
        for word in range(4):
            for row in range(4):
                byte = self.getByteFromHex(word, row, hex_data)
                if row==0:
                    matrix4x4.append([byte])
                else:
                    matrix4x4[word].append(byte)
        return matrix4x4
    
    def matrix4x4ToHex(self, matrix4x4):
        hex_val = 0
        for word in range(4):
            for row in range(4):
                hex_val |= (matrix4x4[word][row] << (128 - 8*(4*word+row) - 8))
        return hex_val
            
    def addRoundKey(self, cipher_state, round_key):
        for word in range(4):
            for row in range(4):
                cipher_state[word][row] ^= round_key[word][row]; 
            
    def subBytes(self, cipher_state):
        for word in range(4):
            for row in range(4):
                cipher_state[word][row] = int(self.CONSTANT["S_BOX"][cipher_state[word][row]], 16); 
        
    def inverseSubBytes(self, cipher_state):
        for word in range(4):
            for row in range(4):
                cipher_state[word][row] = int(self.CONSTANT["INV_S_BOX"][cipher_state[word][row]], 16); 
        
    def shiftRows(self, cipher_state):
        cipher_state[0][1], cipher_state[1][1], cipher_state[2][1], cipher_state[3][1] = cipher_state[1][1], cipher_state[2][1], cipher_state[3][1], cipher_state[0][1]
        cipher_state[0][2], cipher_state[1][2], cipher_state[2][2], cipher_state[3][2] = cipher_state[2][2], cipher_state[3][2], cipher_state[0][2], cipher_state[1][2]
        cipher_state[0][3], cipher_state[1][3], cipher_state[2][3], cipher_state[3][3] = cipher_state[3][3], cipher_state[0][3], cipher_state[1][3], cipher_state[2][3]

    def inverseShiftRows(self, cipher_state):
        cipher_state[0][1], cipher_state[1][1], cipher_state[2][1], cipher_state[3][1] = cipher_state[3][1], cipher_state[0][1], cipher_state[1][1], cipher_state[2][1]
        cipher_state[0][2], cipher_state[1][2], cipher_state[2][2], cipher_state[3][2] = cipher_state[2][2], cipher_state[3][2], cipher_state[0][2], cipher_state[1][2]
        cipher_state[0][3], cipher_state[1][3], cipher_state[2][3], cipher_state[3][3] = cipher_state[1][3], cipher_state[2][3], cipher_state[3][3], cipher_state[0][3]
    
    def xtime(self, byte): 
        if (byte & 0x80):
            return 0xFF & ((byte << 1) ^ 0x1B)
        return (byte << 1)

    def mixColumns(self, cipher_state):
        for col in range(4):
            temp = cipher_state[col][0]
            all_xor = cipher_state[col][0] ^ cipher_state[col][1] ^ cipher_state[col][2] ^ cipher_state[col][3]
            cipher_state[col][0] ^= all_xor ^ self.xtime(cipher_state[col][0] ^ cipher_state[col][1])
            cipher_state[col][1] ^= all_xor ^ self.xtime(cipher_state[col][1] ^ cipher_state[col][2])
            cipher_state[col][2] ^= all_xor ^ self.xtime(cipher_state[col][2] ^ cipher_state[col][3])
            cipher_state[col][3] ^= all_xor ^ self.xtime(cipher_state[col][3] ^ temp)
    
    def inverseMixColumns(self, cipher_state):
        for col in range(4):
            temp1 = self.xtime(self.xtime(cipher_state[col][0] ^ cipher_state[col][2]))
            temp2 = self.xtime(self.xtime(cipher_state[col][1] ^ cipher_state[col][3]))
            cipher_state[col][0] ^= temp1
            cipher_state[col][1] ^= temp2
            cipher_state[col][2] ^= temp1
            cipher_state[col][3] ^= temp2
        self.mixColumns(cipher_state)
        
    def encryptBin(self, plaintext):
        self.plaintext = plaintext

        if len(self.plaintext) != 128 :
            raise ValueError("This implementation of AES supports encryption of 128 bit plaintext only.")

        self.plaintext = int(self.plaintext, 2)
        
        self.cipher_state = self.hexTo4x4Matrix(self.plaintext)
        self.addRoundKey(self.cipher_state, self.round_keys[0:4])
        for round in range(1, self.no_of_rounds+1):
            self.subBytes(self.cipher_state)
            self.shiftRows(self.cipher_state)
            if(round!=self.no_of_rounds):
                self.mixColumns(self.cipher_state)
            self.addRoundKey(self.cipher_state, self.round_keys[4*round:4*(round+1)])
        return self.matrix4x4ToHex(self.cipher_state)

    def decryptBin(self, ciphertext):
        self.ciphertext = ciphertext

        if len(self.ciphertext) != 128 :
            raise ValueError("This implementation of AES supports decryption of 128 bit ciphertext only.")

        self.ciphertext = int(self.ciphertext, 2)

        self.cipher_state = self.hexTo4x4Matrix(self.ciphertext)
        for round in range(self.no_of_rounds, 0, -1):
            self.addRoundKey(self.cipher_state, self.round_keys[4*round:4*(round+1)])
            if(round!=self.no_of_rounds):
                self.inverseMixColumns(self.cipher_state)
            self.inverseShiftRows(self.cipher_state)
            self.inverseSubBytes(self.cipher_state)

        self.addRoundKey(self.cipher_state, self.round_keys[0:4])
        
        return self.matrix4x4ToHex(self.cipher_state)

if __name__ == "__main__":
    '''
    [Sample inputs & outputs]

    1. security parameter (l)
    2. master key for AES (l bits)
    3. choose between encrypt plaintext (0) or decrypt ciphertext (1)
    4. plaintext to encrypt / ciphertext to decrypt (128 bits)

    128
    00101011011111100001010100010110001010001010111011010010101001101010101111110111000101011000100000001001110011110100111100111100
    0
    00110010010000111111011010101000100010000101101000110000100011010011000100110001100110001010001011100000001101110000011100110100

    128
    00101011011111100001010100010110001010001010111011010010101001101010101111110111000101011000100000001001110011110100111100111100
    1
    10101000100100101101111100011111011000000111010000111111101011111110110111010011111101011101010110001101110111011101011011111000

    192
    001010110111111000010101000101100010100010101110110100101010011010101011111101110001010110001000000010011100111101001111001111000010101101111110000101010001011000101000101011101101001010100110
    0
    00110010010000111111011010101000100010000101101000110000100011010011000100110001100110001010001011100000001101110000011100110100

    192
    001010110111111000010101000101100010100010101110110100101010011010101011111101110001010110001000000010011100111101001111001111000010101101111110000101010001011000101000101011101101001010100110
    1
    10001010111101001100011000001000001001011101001000100000010001101111000110001010111111000110011101110011111010011100111111111001
    
    256
    0010101101111110000101010001011000101000101011101101001010100110101010111111011100010101100010000000100111001111010011110011110000101011011111100001010100010110001010001010111011010010101001101010101111110111000101011000100000001001110011110100111100111100
    0
    00110010010000111111011010101000100010000101101000110000100011010011000100110001100110001010001011100000001101110000011100110100

    256
    0010101101111110000101010001011000101000101011101101001010100110101010111111011100010101100010000000100111001111010011110011110000101011011111100001010100010110001010001010111011010010101001101010101111110111000101011000100000001001110011110100111100111100
    1
    10000000100011110111101111101010101011110101111110110110001101010111010101001100011000111001010101110101011101000110010001101110
    '''
    
    security_parameter = input("Security parameter (l = 128, 196 or 256): ")
    master_key = input("Master key (l bits): ")
    myAES = AES(security_parameter, master_key)

    choice = int(input("Enter 0 for encrypting plaintext and 1 for decrypting plaintext: "))

    if choice == 0:
        plaintext = input("Plaint text to encrypt (128 bits): ")
        encryptedtext = myAES.encryptBin(plaintext)
        encryptedtext = str(bin(encryptedtext)[2:])
        encryptedtext = "0" * (128-len(encryptedtext)) + encryptedtext
        print("Encrypted text (128 bits): ", encryptedtext)
    else:
        ciphertext = input("Cipher text to decrypt (128 bits): ")
        decryptedtext = myAES.decryptBin(ciphertext)
        decryptedtext = str(bin(decryptedtext)[2:])
        decryptedtext = "0" * (128-len(decryptedtext)) + decryptedtext
        print("Decrypted text (128 bits): ", decryptedtext)
    
    