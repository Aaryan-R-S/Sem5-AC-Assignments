class Trivium:

    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        self.rounds = 288

        if len(self.key) != 80 or len(self.iv) != 80:
            raise ValueError("This implementation of Trivium supports 80 bit key and iv only.")

        self.key = [int(b) for b in self.key]
        self.iv = [int(b) for b in self.iv]

        self.state = []
        self.state.extend(self.key)
        self.state.extend([0]*13)
        self.state.extend(self.iv)
        self.state.extend([0]*4)
        self.state.extend([0]*108)
        self.state.extend([1]*3)

        self.initState()
        
    def initState(self):
        for r in range(4*self.rounds):
            t1 = self.state[65] ^ (self.state[90] & self.state[91]) ^ self.state[92] ^ self.state[170]
            t2 = self.state[161] ^ (self.state[174] & self.state[175]) ^ self.state[176] ^ self.state[263]
            t3 = self.state[242] ^ (self.state[285] & self.state[286]) ^ self.state[287] ^ self.state[68]

            s1 = self.state[0:92].copy()
            s2 = self.state[93:176].copy()
            s3 = self.state[177:287].copy()

            self.state = [t3] + s1 + [t1] + s2 + [t2] + s3

    def getBit(self):
        t1 = self.state[65] ^ self.state[92]
        t2 = self.state[161] ^ self.state[176]
        t3 = self.state[242] ^ self.state[287]

        z = t1 ^ t2 ^ t3

        t1 = t1 ^ (self.state[90] & self.state[91]) ^  self.state[170]
        t2 = t2 ^ (self.state[174] & self.state[175]) ^  self.state[263]
        t3 = t3 ^ (self.state[285] & self.state[286]) ^  self.state[68]

        s1 = self.state[0:92].copy()
        s2 = self.state[93:176].copy()
        s3 = self.state[177:287].copy()


        self.state = [t3] + s1 + [t1] + s2 + [t2] + s3
        return z
    
    def getBits(self, param_l):
        param_l = int(param_l)
        # if param_l < 1 or param_l > (1<<15):
        #     raise ValueError("This implementation of Trivium supports param_l in [1, 2^15] range only.")
    
        output_stream = ""

        for b in range(param_l):
            output_stream += str(self.getBit())
            
        return output_stream
        
if __name__ == "__main__":
    '''
    [Sample inputs & outputs]

    1. Key for Trivium (80 bits)
    2. Initialization vector (80 bits)
    3. Lenth of output bit stream (l where 1 ≤ l ≤ 2^15)

    00000000000001000101011000111001000110000010010001001111010000000000000000000000
    00000000000000000000000000000000000000000000000000000000000000000000000000000000
    1000
    0011010000000011100010010011000100110000001001101111011000000110101110011011011000110100010001001001111111111101110010100101000110010110000000110000111100101010101001110111100100100001001110000110000101110100001000000100011001101110011010100100101110111001001100100000000010011110011010110000011011001011001110000101100111011111111011111001100101010111110101100001011100111110101110111100111111101010100000011001101110010100101110101011010101011010001110011110111111101111100111111111101110101100111111000001011110100101011011001110111110011111110110001110111111011100100101001011001111110111000110100011001001101010100001000111100011100001111100001011100011011010011010100110010000000010100110010110001000100000111111011010110011010100001010110011000001100101100001111011011000100011001010110000110000000010011010110000011111111010001010001000101011001001011000111110100001010000101011010010101000101101010100001000110110100110100111100101110000010011011000001001010100011011001000011110001100110101
    '''

    key = input("Key (80 bits): ")
    iv = input("IV (80 bits): ")
    myTrivium = Trivium(key, iv)

    param_l = input("Length of output bit stream: ")
    bit_stream = myTrivium.getBits(param_l)
    print("Output bit stream: ", len(bit_stream))
    
    