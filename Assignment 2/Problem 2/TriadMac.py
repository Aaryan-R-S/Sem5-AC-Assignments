con = [
    1,1,1,1,1,1,1,0,
    1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1
]

def to8bitArr(num):
    result = []
    for i in range(7,-1,-1):
        if ((num>>i)&1) == 0:
            result.append(0)
        else:
            result.append(1)
    return result

def byteLengthPad(m):
    mB = m
    l = len(m)
    mB.append(to8bitArr(l&0xFF)) 
    mB.append(to8bitArr((l>>8)&0xFF)) 
    mB.append(to8bitArr((l>>16)&0xFF)) 
    mB.append(to8bitArr((l>>24)&0xFF)) 
    mB.append(to8bitArr((l>>32)&0xFF)) 
    mB.append(to8bitArr((l>>40)&0xFF)) 
    mB.append(to8bitArr((l>>48)&0xFF)) 
    return mB

def TriadUpd(a, b, c, msg):

    t1 = a[68] ^ a[80] ^ (b[85] & c[85])
    t2 = b[64] ^ b[88]
    t3 = c[68] ^ c[88]
    
    z = t1 ^ t2 ^ t3

    t1 = t1 ^ (a[73] & a[79]) ^ b[66] ^ msg
    t2 = t2 ^ (b[65] & b[87]) ^ c[84] ^ msg
    t3 = t3 ^ (c[77] & c[87]) ^ a[74] ^ msg
    
    a = [0, t3] + a[1:80]
    b = [0, t1] + b[1:88]
    c = [0, t2] + c[1:88]

    return (a, b, c, z)
    
def TriadPB(a, b, c):
    
    (a, b, c, z) = TriadUpd(a, b, c, 1)

    for _ in range(2, 1024+1):
        (a, b, c, z) = TriadUpd(a, b, c, 0)
        
    return (a, b, c)

def TriadMAC(K, N, M, A):
    if len(K) != 128 or len(N) != 96:
        raise ValueError("[ERROR] Key size must be 128 bits and nonce size must be 96 bits!")
            
    a = [0] + N[0*8:0*8+8] + K[4*8:4*8+8] + con[3*8:3*8+8] + K[3*8:3*8+8] + con[2*8:2*8+8] + K[2*8:2*8+8] + con[1*8:1*8+8] + K[1*8:1*8+8] + con[0*8:0*8+8] + K[0*8:0*8+8]

    b = [0]
    for i in range(11, 0, -1):
        b.extend(N[i*8 : i*8+8])
        
    c = [0]
    for i in range(15, 4, -1):
        c.extend(K[i*8 : i*8+8])

    (a, b, c) = TriadPB(a, b, c)
    
    mlen = len(M) 
    adlen = len(A) 

    AB = byteLengthPad(A)
    
    for i in range(adlen+7):
        for j in range(7,-1,-1):
            (a, b, c, z) = TriadUpd(a, b, c, AB[i][j])
            
    for i in range(mlen):
        for j in range(7,-1,-1):
            (a, b, c, z) = TriadUpd(a, b, c, M[i][j])

    (a, b, c) = TriadPB(a, b, c)

    w, h = 8, 8
    T = [[0 for x in range(w)] for y in range(h)] 

    for i in range(8):
        for j in range(7,-1,-1):
            (a, b, c, T[i][j]) = TriadUpd(a, b, c, 0)
    
    return T
      
if __name__ == "__main__":
    '''
    [Sample inputs & outputs]
    INPUT #1
    00000010101100000100010001010110001110010001100000110010001100111101111000100001011110110001010000100100100000001111010101101010
    000000000000010001010110001110010001100000100100010011110100000000000000000000001111010101101010
    0011010000000011100010010011000100110000001001101111011000000110101110011011011000110100010001001001111111111101110010100101000110010110000000110000111100101010101001110111100100100001001110000110000101110100001000000100011001101110011010100100101110111001001100100000000010011110011010110000011011001011001110000101100111011111111011111001100101010111110101100001011100111110101110111100111111101010100000011001101110010100101110101011010101011010001110011110111111101111100111111111101110101100111111000001011110100101011011001110111110011111110110001110111111011100100101001011001111110111000110100011001001101010100001000111100011100001111100001011100011011010011010100110010000000010100110010110001000100000111111011010110011010100001010110011000001100101100001111011011000100011001010110000110000000010011010110000011111111010001010001000101011001001011000111110100001010000101011010010101000101101010100001000110110100110100111100101110000010011011000001001010100011011001000011110001100110101
    0011010000000011100010010011000100110000000101011010010101000101101010100001000110110100110100111100101110000010011011000001001010100011011001000011110001100110

    OUTPUT #1
    0111100010001001001000011110101000101011010011101101111110011010

    INPUT #2
    00000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111
    000000000000000100000010000000110000010000000101000001100000011100001000000010010000101000001011
    00000000
    00000000

    OUTPUT #2
    1101010000011010111100000000000111011001110101110101001101100111

    INPUT #3
    00000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111
    000000000000000100000010000000110000010000000101000001100000011100001000000010010000101000001011



    OUTPUT #3
    1101000101101101110011001010011010110011001101001100101110000100
    '''

    key = [int(i) for i in list(input("\nKey (16 bytes or 128 bits binary string): "))]
    nonce = [int(i) for i in list(input("\nNonce (12 bytes or 96 bits binary string): "))]

    message = [int(i) for i in list(input("\nMessage (binary string with size multiple of 8): "))]
    if(len(message)%8 != 0):
        raise ValueError("[ERROR] Message size must be mulitple of 8!")
    message = [[message[8*i+j] for j in range(8)] for i in range(0, int(len(message)/8), 8)]

    associated_data = [int(i) for i in list(input("\nAssociated Data (binary string with size multiple of 8): "))]
    if(len(associated_data)%8 != 0):
        raise ValueError("[ERROR] Associated data size must be mulitple of 8!")
    associated_data = [[associated_data[8*i+j] for j in range(8)] for i in range(0, int(len(associated_data)/8), 8)]

    myTag = TriadMAC(key, nonce, message, associated_data)
    myTag = ''.join(str(b) for B in myTag for b in B)
    print(f"\nTag: {myTag}\n")
