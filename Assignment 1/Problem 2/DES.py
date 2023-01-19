import json
 
class DES:
    
    with open('constants.json') as json_file:
        CONSTANT = json.load(json_file)

    def __init__(self, master_key):
        self.master_key = master_key
        self.rounds = 16
        
        if len(self.master_key) != 56:
            raise ValueError("This implementation of DES supports 56 bit key only.")

        self.master_key = [int(b) for b in self.master_key]
        self.round_keys = self.generateRoundKeys()

    def permuteArray(self, to_permute, permute_by):
        return [to_permute[idx-1] for idx in permute_by]

    def expandArray(self, to_expand, expand_by):
        return [to_expand[idx-1] for idx in expand_by]

    def xorArrays(self, arr_1, arr_2):
        return [b1^b2 for b1,b2 in zip(arr_1, arr_2)]

    def substituteArray(self, to_substitute, substitute_by):
        ret_val = []
        for six_bits in range(len(substitute_by)):
            row = 2 * to_substitute[6*six_bits] + to_substitute[6*six_bits+5]
            col = 8 * to_substitute[6*six_bits+1] + 4 * to_substitute[6*six_bits+2] + 2 * to_substitute[6*six_bits+3] + to_substitute[6*six_bits+4]
            four_bits = substitute_by[six_bits][row][col]
            four_bits = "{0:b}".format(four_bits)
            four_bits =  "0" * (4-len(four_bits)) + four_bits
            ret_val.extend([int(b) for b in four_bits])
        return ret_val

    def generateRoundKeys(self):
        r_keys = []
        
        r_key_init = self.master_key
        left_block = r_key_init[:28]
        right_block = r_key_init[28:]

        for r in range(self.rounds):
            shift_by = DES.CONSTANT["KEY_SHIFT"][r]
            left_block = left_block[shift_by:] + left_block[:shift_by]
            right_block = right_block[shift_by:] + right_block[:shift_by]  
            
            r_keys.append(self.permuteArray(left_block + right_block, DES.CONSTANT["ROUND_KEY_PERMUTE"]))

        return r_keys
        
    def encryptBin(self, plaintext):
        self.plaintext = plaintext

        if len(self.plaintext) != 64 :
            raise ValueError("This implementation of DES supports encryption of 64 bit plaintext only.")

        self.plaintext = [int(b) for b in self.plaintext]
        
        self.cipher_state = self.permuteArray(self.plaintext, DES.CONSTANT["INIT_PERMUTE"])
        left_block = self.cipher_state[:32]
        right_block = self.cipher_state[32:]
        temp_block = []

        for r in range(self.rounds):
            expanded_right_block = self.expandArray(right_block, DES.CONSTANT["EXPANSION_BOX"])
            
            temp_block = self.xorArrays(self.round_keys[r], expanded_right_block)
            temp_block = self.substituteArray(temp_block, DES.CONSTANT["S_BOX"])
            temp_block = self.permuteArray(temp_block, DES.CONSTANT["ROUND_PERMUTE"])
            temp_block = self.xorArrays(temp_block, left_block)

            left_block = right_block
            right_block = temp_block
            self.cipher_state = left_block + right_block

        self.cipher_state = self.permuteArray(right_block + left_block, DES.CONSTANT["FINAL_PERMUTE"])

        encrypted_text = "".join(map(str, self.cipher_state))
        return encrypted_text

    def decryptBin(self, ciphertext):
        self.ciphertext = ciphertext

        if len(self.ciphertext) != 64 :
            raise ValueError("This implementation of DES supports decryption of 64 bit ciphertext only.")

        self.ciphertext = [int(b) for b in self.ciphertext]
        
        self.cipher_state = self.permuteArray(self.ciphertext, DES.CONSTANT["INIT_PERMUTE"])
        left_block = self.cipher_state[:32]
        right_block = self.cipher_state[32:]
        temp_block = []

        for r in range(self.rounds):
            expanded_right_block = self.expandArray(right_block, DES.CONSTANT["EXPANSION_BOX"])

            temp_block = self.xorArrays(self.round_keys[self.rounds-r-1], expanded_right_block)
            temp_block = self.substituteArray(temp_block, DES.CONSTANT["S_BOX"])
            temp_block = self.permuteArray(temp_block, DES.CONSTANT["ROUND_PERMUTE"])
            temp_block = self.xorArrays(temp_block, left_block)

            left_block = right_block
            right_block = temp_block
            self.cipher_state = left_block + right_block

        self.cipher_state = self.permuteArray(right_block + left_block, DES.CONSTANT["FINAL_PERMUTE"])

        decrypted_text = "".join(map(str, self.cipher_state))
        return decrypted_text


class TripleDES:
    def __init__(self, master_key_1, master_key_2, master_key_3):
        self.master_key_1 = master_key_1
        self.master_key_2 = master_key_2
        self.master_key_3 = master_key_3
        self.myDES_1 = DES(master_key_1)
        self.myDES_2 = DES(master_key_2)
        self.myDES_3 = DES(master_key_3)

    def encryptBin(self, plaintext):
        self.cipher_state = plaintext
        self.cipher_state = self.myDES_1.encryptBin(self.cipher_state)
        self.cipher_state = self.myDES_2.decryptBin(self.cipher_state)
        self.cipher_state = self.myDES_3.encryptBin(self.cipher_state)
        return self.cipher_state

    def decryptBin(self, ciphertext):
        self.cipher_state = ciphertext
        self.cipher_state = self.myDES_3.decryptBin(self.cipher_state)
        self.cipher_state = self.myDES_2.encryptBin(self.cipher_state)
        self.cipher_state = self.myDES_1.decryptBin(self.cipher_state)
        return self.cipher_state

if __name__ == "__main__":
    '''
    [Sample inputs & outputs]

    1. master key for DES (56 bits)
    2. choose between encrypt plaintext (0) or decrypt ciphertext (1)
    3. plaintext to encrypt / ciphertext to decrypt (128 bits)

    00101011011111100001010100010110001010001010111011010010
    00101100010100010101110110100100010101101111110000101010
    10111011010010001010110111111000010101000101100010100010
    0
    0011001001000011111101101010100010001000010110100011000010001101
    1110010001000111100011100111101011010111101110000110101110001011

    00101011011111100001010100010110001010001010111011010010
    00101100010100010101110110100100010101101111110000101010
    10111011010010001010110111111000010101000101100010100010
    1
    1110010001000111100011100111101011010111101110000110101110001011
    0011001001000011111101101010100010001000010110100011000010001101

    '''

    master_key_1 = input("Master key #1 (56 bits): ")
    master_key_2 = input("Master key #2 (56 bits): ")
    master_key_3 = input("Master key #3 (56 bits): ")
    myTripleDES = TripleDES(master_key_1, master_key_2, master_key_3)

    choice = int(input("Enter 0 for encrypting plaintext and 1 for decrypting plaintext: "))

    if choice == 0:
        plaintext = input("Plaint text to encrypt (64 bits): ")
        encryptedtext = myTripleDES.encryptBin(plaintext)
        print("Encrypted text (64 bits): ", encryptedtext)
    else:
        ciphertext = input("Cipher text to decrypt (64 bits): ")
        decryptedtext = myTripleDES.decryptBin(ciphertext)
        print("Decrypted text (64 bits): ", decryptedtext)
    
    