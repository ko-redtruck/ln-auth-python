#der encoded ecdsa signature --> int base 10 pair
def decode_signature(s):
    length = int(s[2:4],base=16)

    marker = s[0:2]
    #marker1 = s[4:6]
    #marker2 = s[8+length_1*2:10+length_1*2]

    length_1 = int(s[6:8],base=16)
    length_2 = int(s[10+length_1*2:12+length_1*2],base=16)

    number_1 = int(s[8:8+length_1*2],base=16)
    number_2 = int(s[12+length_1*2:12+length_1*2+length_2*2],base=16)
    #number_2 = int(s[12+length_1*2:],base=16)

    return number_1,number_2
