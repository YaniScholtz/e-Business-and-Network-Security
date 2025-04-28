import numpy as np
import string


# ----------------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------------


"""
IMPORTANT!!
- Code submission due on Tuesday 29 April 2025, before 8h30, on AMS and ClickUP
- Prac test is two hours later at 10h30.
- Rename this file to <insertyourstudentnumberhere>_Prac_2.py
- submit .py on AMS, .pdf on ClickUP
- Comment your code (best practice)

- Use the function definitions given here/specified in the guide.
- DO NOT CHANGE THEM / USE DIFFERENT DATA TYPES!! For example, using lists instead of np.ndarrays

- Please read the practical guide for instructions.
- Unanswered questions? Email me (Miss Elna Fourie) at: u19049910@tuks.co.za
 
Changelog:
- 2024/04/17 --> replaced 'pass' with 'raise Exception()' for all functions
             --> For AES and DES Encrypt/Decrypt String/Image: load given *.npy arrays within functions
                    --> DO NOT CHANGE THE NP.LOAD() FUNCTIONS' FILE PATH, USE AS GIVEN
 
"""


# ----------------------------------------------------------------------------------------------
# 3.1 AES Cipher
# ----------------------------------------------------------------------------------------------


def aes_Generate_Round_Keys(key: str, sBox: np.ndarray) -> np.ndarray:  # 1
    rcon = [
        0x01,
        0x02,
        0x04,
        0x08,
        0x10,
        0x20,
        0x40,
        0x80,
        0x1B,
        0x36,
        0x6C,
        0xD8,
        0xAB,
        0x4D,
    ]
    keybytes = []
    # Converting into ascii values
    for c in key:
        ascii = ord(c)
        keybytes.append(ascii)

    w = []
    # First 8 words is directly from keys
    for i in range(8):
        w.append(keybytes[4 * i : 4 * i + 4])
    # Generating 60 wors
    for i in range(8, 4 * (14 + 1)):
        temp = list(w[i - 1])
        # rotate bytes,sub,xor  with rcon
        if i % 8 == 0:
            temp = temp[1:] + temp[:1]

            newtemp = []
            for byte in temp:
                row = int(byte / 16)
                col = byte % 16
                sboxvalue = sBox[row][col]
                substituted = int(sboxvalue, 16)
                newtemp.append(substituted)

            temp = newtemp
            temp[0] ^= rcon[int(i / 8) - 1]

        elif i % 8 == 4:
            newtemp = []

            for byte in temp:
                row = int(byte / 16)
                col = byte % 16
                sboxvalue = sBox[row][col]
                newtemp.append(int(sboxvalue, 16))

            temp = newtemp

        newword = []

        prevword = w[i - 8]

        for j in range(4):
            xor_result = prevword[j] ^ temp[j]
            newword.append(xor_result)
        w.append(newword)

    rkeyss = []
    # final round keys
    for r in range(14 + 1):
        round_matrix = []
        for i in range(4):
            row = [0, 0, 0, 0]
            round_matrix.append(row)
        # Filling igt by the columns
        for c in range(4):
            word = w[r * 4 + c]
            for r_index in range(4):
                round_matrix[r_index][c] = word[r_index]

        rkeyss.append(np.array(round_matrix))

    return np.array(rkeyss)


def aes_Preprocess_String_Plaintext(plaintext: str) -> np.ndarray:  # 2
    intarr = []

    for char in plaintext:
        ascii = ord(char)
        intarr.append(ascii)

    currentlen = len(intarr)
    remainder = currentlen % 16
    if remainder == 0:
        padlen = 16
    else:
        padlen = 16 - remainder

    for i in range(padlen):
        intarr.append(padlen)

    return np.array(intarr)


def aes_Create_Input_States(inputBytes: np.ndarray) -> np.ndarray:  # 3

    totallen = len(inputBytes)
    numberofblocks = int(totallen / 16)

    allStates = []

    for block_index in range(numberofblocks):
        # Getting one block
        block = inputBytes[block_index * 16 : (block_index + 1) * 16]

        onestaeteblock = []
        # Rearranging into column again
        for col in range(4):
            column = [
                block[col],
                block[col + 4],
                block[col + 8],
                block[col + 12],
            ]
            onestaeteblock.append(column)

        allStates.append(onestaeteblock)

    return np.array(allStates)


def aes_remove_Padding(paddedArray: np.ndarray) -> np.ndarray:  # 4
    totallen = len(paddedArray)
    last_index = totallen - 1
    # Getting the last index to see how much padding there is
    paddingvalue = paddedArray[last_index]
    newlen = totallen - paddingvalue

    unpadded = []
    counter = 0
    # Filling up new array witout padding
    while counter < newlen:
        value = paddedArray[counter]
        unpadded.append(value)
        counter = counter + 1

    final = np.array(unpadded)

    return np.array(final)


def aes_Encrypt_String(plaintext: str, key: str) -> np.ndarray:  # 5

    sBox = np.load("AES_Arrays\\AES_Sbox_lookup.npy")

    keys = aes_Generate_Round_Keys(key, sBox)
    paddedplaint = aes_Preprocess_String_Plaintext(plaintext)
    stateforInput = aes_Create_Input_States(paddedplaint)

    index = 0
    cipher = []

    while index < len(stateforInput):

        current = stateforInput[index]
        encrypted = aes_Encrypt_State(current, keys, sBox)

        position = 0
        while position < 4:
            # Getting it into a 4x4 matrix again that is columns wise
            cipher.append(encrypted[0][position])
            cipher.append(encrypted[1][position])
            cipher.append(encrypted[2][position])
            cipher.append(encrypted[3][position])
            position += 1

        index += 1

    return np.array(cipher)


def aes_Decrypt_String(ciphertext: np.ndarray, key: str) -> str:  # 6
    sBox = np.load("AES_Arrays\\AES_Sbox_lookup.npy")
    invsBox = np.load("AES_Arrays\\AES_Inverse_Sbox_lookup.npy")
    # Same as encrypt string just with removing padding at the end

    keys = aes_Generate_Round_Keys(key, sBox)
    allStates = aes_Create_Input_States(ciphertext)

    decryptedb = []
    index = 0

    while index < len(allStates):

        current_state = allStates[index]
        decrypted = aes_Decrypt_State(current_state, keys, invsBox)

        position = 0
        while position < 4:
            decryptedb.append(decrypted[0][position])
            decryptedb.append(decrypted[1][position])
            decryptedb.append(decrypted[2][position])
            decryptedb.append(decrypted[3][position])
            position += 1

        index += 1

    unpad = aes_remove_Padding(decryptedb)

    return "".join(chr(b) for b in unpad)


def aes_Preprocess_Image_Plaintext(plaintext: np.ndarray) -> np.ndarray:  # 7
    flat = plaintext.flatten()
    # Same as the preprocess string but with the flattened image
    flat = list(flat)

    length = len(flat)
    remainder = length % 16
    if remainder == 0:
        padlen = 16
    else:
        padlen = 16 - remainder

    # padding = [padlen] * padlen
    # padded = flat + padding

    for i in range(padlen):
        flat.append(padlen)

    return np.array(flat)


def aes_Encrypt_Image(plaintext: np.ndarray, key: str) -> np.ndarray:  # 8
    sBox = np.load("AES_Arrays\\AES_Sbox_lookup.npy")
    # Same as the encrypt string but just with the preprocess images
    keys = aes_Generate_Round_Keys(key, sBox)
    paddedplain = aes_Preprocess_Image_Plaintext(plaintext)
    cipher = []
    stateforInput = aes_Create_Input_States(paddedplain)

    index = 0
    cipher = []

    while index < len(stateforInput):

        current = stateforInput[index]
        encrypted = aes_Encrypt_State(current, keys, sBox)

        position = 0
        while position < 4:
            cipher.append(encrypted[0][position])
            cipher.append(encrypted[1][position])
            cipher.append(encrypted[2][position])
            cipher.append(encrypted[3][position])
            position += 1

        index += 1

    return np.array(cipher)


def aes_Decrypt_Image(ciphertext: np.ndarray, key: str) -> np.ndarray:  # 9
    sBox = np.load("AES_Arrays\\AES_Sbox_lookup.npy")
    invsBox = np.load("AES_Arrays\\AES_Inverse_Sbox_lookup.npy")
    # Same as decrypt string
    keys = aes_Generate_Round_Keys(key, sBox)
    inputs = aes_Create_Input_States(ciphertext)

    decryptedb = []
    index = 0

    while index < len(inputs):
        current_state = inputs[index]
        decrypted = aes_Decrypt_State(current_state, keys, invsBox)

        for col in range(4):
            decryptedb.append(decrypted[0][col])
            decryptedb.append(decrypted[1][col])
            decryptedb.append(decrypted[2][col])
            decryptedb.append(decrypted[3][col])
        index += 1

    unpadded = aes_remove_Padding(decryptedb)

    return np.array(unpadded)


def aes_Add_Round_key(state: np.ndarray, roundKey: np.ndarray) -> np.ndarray:  # 10
    return np.array(state ^ roundKey)


def aes_Substitute_Bytes(state: np.ndarray, sBox: np.ndarray) -> np.ndarray:  # 11

    outpute = []

    for row in state:
        transformed = []

        for byte in row:

            bytehex = hex(byte)[2:].upper().zfill(2)
            # Getting the row and col for the sbox subs
            sboxrow = int(bytehex[0], 16)
            sboxcol = int(bytehex[1], 16)
            # Getting the substituted values from sBox
            subs = int(sBox[sboxrow][sboxcol], 16)

            transformed.append(subs)

        outpute.append(transformed)

    return np.array(outpute)


def aes_Shift_Rows_Encrypt(state: np.ndarray) -> np.ndarray:  # 12
    shifted = []
    # First row has not shifts
    shifted.append(state[0])
    # Second row has 1 shift and so on for the rest of the rows
    row1 = state[1].tolist()
    shifted.append(row1[1:] + row1[:1])

    row2 = state[2].tolist()
    shifted.append(row2[2:] + row2[:2])

    row3 = state[3].tolist()
    shifted.append(row3[3:] + row3[:3])

    return np.array(shifted)


def aes_Shift_Rows_Decrypt(state: np.ndarray) -> np.ndarray:  # 13
    shifted = []
    # The same as rhe encrypt but going in reverse and shifting it to the right

    shifted.append(state[0])
    row1 = state[1].tolist()
    shifted.append([row1[-1]] + row1[:-1])

    row2 = state[2].tolist()
    shifted.append([row2[-2], row2[-1]] + row2[:-2])

    row3 = state[3].tolist()
    shifted.append([row3[-3], row3[-2], row3[-1]] + row3[:-3])

    return np.array(shifted)


def aes_Mix_Columns_Encrypt(state: np.ndarray) -> np.ndarray:  # 14

    def gfmul(a: int, b: int) -> int:
        result = 0

        for i in range(8):  # For the 8 bits in a byte

            if b % 2 == 1:  # Least significant bits is 1
                result = result ^ a

            high = a >= 128

            a = a * 2

            if high:
                a = a ^ 0x11B

            a = a % 256

            b = int(b / 2)

        return result

    mix = np.array([[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]])

    mstate = np.zeros_like(state)

    for col in range(4):
        for row in range(4):
            value = 0
            for k in range(4):
                byte = int(state[k][col])  # byte from original state
                coef = int(mix[row][k])  # From mix matrix
                value ^= gfmul(byte, coef)
            mstate[row][col] = value

    return np.array(mstate)


def aes_Mix_Columns_Decrypt(state: np.ndarray) -> np.ndarray:  # 15
    # Same as the encrypt but just using the invmix
    inv_mix = np.array(
        [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]
    )

    def gfmul(a: int, b: int) -> int:
        result = 0

        for i in range(8):

            if b % 2 == 1:
                result = result ^ a

            high = a >= 128

            a = a * 2

            if high:
                a = a ^ 0x11B

            a = a % 256

            b = int(b / 2)

        return result

    decrypted = np.zeros_like(state)

    for col in range(4):
        for row in range(4):
            val = 0
            for k in range(4):
                val ^= gfmul(state[k][col], inv_mix[row][k])
            decrypted[row][col] = val

    return np.array(decrypted)


def aes_Apply_Encryption_Round(
    state: np.ndarray, roundKey: np.ndarray, sBox: np.ndarray
) -> np.ndarray:  # 16

    subval = aes_Substitute_Bytes(state, sBox)

    shift = aes_Shift_Rows_Encrypt(subval)

    mixval = aes_Mix_Columns_Encrypt(shift)

    xor = aes_Add_Round_key(mixval, roundKey)

    return np.array(xor)


def aes_Encrypt_State(
    state: np.ndarray, roundKeys: np.ndarray, sBox: np.ndarray
) -> np.ndarray:  # 17

    round0 = aes_Add_Round_key(state, roundKeys[0])
    rounds = round0

    for r in range(1, 14):

        rounds = aes_Apply_Encryption_Round(rounds, roundKeys[r], sBox)

    subval = aes_Substitute_Bytes(rounds, sBox)

    shif = aes_Shift_Rows_Encrypt(subval)

    xor = aes_Add_Round_key(shif, roundKeys[14])

    return np.array(xor)


def aes_Apply_Decryption_Round(
    state: np.ndarray, roundKey: np.ndarray, sBox: np.ndarray
) -> np.ndarray:  # 18

    shift = aes_Shift_Rows_Decrypt(state)
    sub = aes_Substitute_Bytes(shift, sBox)
    xor = aes_Add_Round_key(sub, roundKey)
    mix = aes_Mix_Columns_Decrypt(xor)
    return np.array(mix)


def aes_Decrypt_State(
    state: np.ndarray, roundKeys: np.ndarray, sBox: np.ndarray
) -> np.ndarray:  # 19

    roun14 = aes_Add_Round_key(state, roundKeys[14])
    rounds = roun14

    for i in range(13, 0, -1):
        rounds = aes_Apply_Decryption_Round(rounds, roundKeys[i], sBox)

    shift = aes_Shift_Rows_Decrypt(rounds)
    subb = aes_Substitute_Bytes(shift, sBox)
    finalxor = aes_Add_Round_key(subb, roundKeys[0])

    return np.array(finalxor)


def aes_des_rc4_Convert_To_Image(
    arrayToConvert: np.ndarray, originalShape: tuple
) -> np.ndarray:  # 20
    input_length = len(arrayToConvert)
    height = originalShape[1]
    width = originalShape[2]
    block_area = height * width

    leftover_values = input_length % block_area
    padding_amount = block_area - leftover_values if leftover_values != 0 else 0

    for i in range(padding_amount):
        arrayToConvert = np.append(arrayToConvert, [padding_amount])

    reshaped_array = np.reshape(arrayToConvert, (-1, height, width))

    return reshaped_array


# key = "qwertyuiopasdfghjklzxcvbnmnbvcxz"
# cipher_hex = "Googgooddaymmmm"

# result = aes_Encrypt_String(cipher_hex, key)
# dectryp = aes_Decrypt_String(result, key)
# result = "".join(format(byte, "02x") for byte in result).upper()

# print(result)
# print(dectryp)

# test_img = np.random.randint(0, 256, size=(2, 2, 3), dtype=np.uint8)
# print("Original Test Image:")
# print(test_img)

# # 2. Create key
# key = "ABCDEFGHIJKLMNOPQRSTUVWX12345678"

# # 3. Encrypt
# ciphertext = aes_Encrypt_Image(test_img, key)
# print("Ciphertext:")
# print(ciphertext)

# # 4. Decrypt
# decrypted_flat = aes_Decrypt_Image(ciphertext, key)
# decrypted_img = aes_des_rc4_Convert_To_Image(decrypted_flat, test_img.shape)

# print("Decrypted Image:")
# print(decrypted_img)

# # 5. Compare
# if np.array_equal(test_img, decrypted_img):
#     print("✅ Test Passed: Decrypted matches original.")
# else:
#     print("❌ Test Failed: Decrypted does not match original.")
# ----------------------------------------------------------------------------------------------
# 3.2 DES Cipher
# ----------------------------------------------------------------------------------------------


def des_Generate_Round_Keys(
    key: str, permutedChoice1, permutedChoice2, roundShifts
) -> np.ndarray:  # 1

    keys = []

    binkey = ""
    for c in key:
        # Getting the ascii values
        ascii = ord(c)
        # turning it into a binary
        binarystr = format(ascii, "08b")
        binkey += binarystr

    firstperm = ""
    # for the first permuted choice
    for index in permutedChoice1:
        bit = binkey[index - 1]
        firstperm += bit
    # Splitting up gfor spearate shifts
    C, D = firstperm[:28], firstperm[28:]

    for shift in roundShifts:
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]
        combined = C + D

        keybinrou = ""
        # now doing the second permutation choice
        for i in range(len(permutedChoice2)):
            position = permutedChoice2[i] - 1
            keybinrou += combined[position]
        keyhex = hex(int(keybinrou, 2))[2:].upper().zfill(12)
        keys.append(keyhex)

    return np.array(keys)


def des_Preprocess_String_Plaintext(plaintext: str) -> np.ndarray:  # 2
    intarr = []
    # Very similar and same procedure as the aes preprocess string just with converting
    # it now to a hex before returning

    for char in plaintext:
        ascii = ord(char)
        intarr.append(ascii)

    clen = len(intarr)
    remainder = clen % 8
    if remainder == 0:
        padlen = 8
    else:
        padlen = 8 - remainder

    for i in range(padlen):
        intarr.append(padlen)

    hexarr = []
    for val in intarr:
        hexstring = format(val, "02X")
        hexarr.append(hexstring)

    return np.array(hexarr)


def des_Create_Input_Blocks(processedArray: np.ndarray) -> np.ndarray:  # 3
    size = 8
    # Getting block legnth
    numblocks = int(len(processedArray) / size)
    blocks = []
    # Creating an array consisting of 8 size blocks
    for i in range(numblocks):
        start = i * size
        end = start + size
        current_block = processedArray[start:end]
        combined = "".join(current_block)
        blocks.append(combined)

    return np.array(blocks)


def des_Remove_String_Padding(paddedArray: np.ndarray) -> np.ndarray:  # 4
    # Same algorithm and concept as the aes removing padding
    totallength = len(paddedArray)
    lastindex = totallength - 1
    padding = int(paddedArray[lastindex], 16)
    newlen = totallength - padding
    unpad = []
    for i in range(newlen):
        unpad.append(paddedArray[i])

    return np.array(unpad)


def des_Encrypt_String(plaintext: str, key: str) -> np.ndarray:  # 5
    keyPermChoice1 = np.load("DES_Arrays\\DES_Key_Permutation_Choice_1.npy")
    keyPermChoice2 = np.load("DES_Arrays\\DES_Key_Permutation_Choice_2.npy")
    keyRoundShifts = np.load("DES_Arrays\\DES_Round_Shifts.npy")
    sBoxes = np.load("DES_Arrays\\DES_sBoxes.npy")
    Fexpansio4ox = np.load("DES_Arrays\\DES_Expansion_Box.npy")
    FpermutationChoice = np.load("DES_Arrays\\DES_F_Function_Permutation.npy")
    initPerm = np.load("DES_Arrays\\DES_Initial_Permutation.npy")
    invInitPerm = np.load("DES_Arrays\\DES_Inverse_Initial_Permutation.npy")

    cipher = []

    keys = des_Generate_Round_Keys(key, keyPermChoice1, keyPermChoice2, keyRoundShifts)

    paddedplain = des_Preprocess_String_Plaintext(plaintext)
    blocks = des_Create_Input_Blocks(paddedplain)
    # Getting the blocks and processing each one and encrypting it
    for block in blocks:
        blockhex = "".join(b.upper() for b in block)
        cipherblock = des_Process_Block(
            blockhex,
            keys,
            initPerm,
            sBoxes,
            Fexpansio4ox,
            FpermutationChoice,
            invInitPerm,
        )
        for i in range(0, len(cipherblock), 2):
            # wo_chars = cipherblock[i : i + 2]
            cipher.append(cipherblock[i : i + 2].upper())

    return np.array(cipher)


def des_Decrypt_String(ciphertext: np.ndarray, key: str) -> str:  # 6
    keyPermChoice1 = np.load("DES_Arrays\\DES_Key_Permutation_Choice_1.npy")
    keyPermChoice2 = np.load("DES_Arrays\\DES_Key_Permutation_Choice_2.npy")
    keyRoundShifts = np.load("DES_Arrays\\DES_Round_Shifts.npy")
    sBoxes = np.load("DES_Arrays\\DES_sBoxes.npy")
    Fexpansio4ox = np.load("DES_Arrays\\DES_Expansion_Box.npy")
    FpermutationChoice = np.load("DES_Arrays\\DES_F_Function_Permutation.npy")
    initPerm = np.load("DES_Arrays\\DES_Initial_Permutation.npy")
    invInitPerm = np.load("DES_Arrays\\DES_Inverse_Initial_Permutation.npy")

    plaintext = []
    # Same algorithm as the encrypt string

    keys = des_Generate_Round_Keys(key, keyPermChoice1, keyPermChoice2, keyRoundShifts)
    keys = keys[::-1]

    blocks = des_Create_Input_Blocks(ciphertext)

    for block in blocks:
        blockhex = "".join(b.upper() for b in block)
        plaintextblock = des_Process_Block(
            blockhex,
            keys,
            initPerm,
            sBoxes,
            Fexpansio4ox,
            FpermutationChoice,
            invInitPerm,
        )

        for i in range(0, len(plaintextblock), 2):
            plaintext.append(plaintextblock[i : i + 2])

    unpad = des_Remove_String_Padding(np.array(plaintext))
    # Getting it into a string format
    plain = ""
    for hex in unpad:
        plain += chr(int(hex, 16))

    return plain


def des_Process_Block(
    block: str,
    roundKeys: np.ndarray,
    initialPerm: np.ndarray,
    sBoxes: np.ndarray,
    expansio4ox: np.ndarray,
    FpermChoice: np.ndarray,
    invInitialPerm: np.ndarray,
) -> str:  # 7

    permuted = des_Apply_Permutation(block, initialPerm, 64)

    for k in range(16):
        permuted = des_Process_Round(
            permuted, roundKeys[k], sBoxes, expansio4ox, FpermChoice
        )

    half = int(len(permuted) / 2)
    swapped = permuted[half:] + permuted[:half]

    final = des_Apply_Permutation(swapped, invInitialPerm, 64)

    return final


def des_Process_Round(
    roundInputValue: str,
    roundKey: str,
    sBoxes: np.ndarray,
    expansio4ox: np.ndarray,
    permutationChoice: np.ndarray,
) -> str:  # 8
    # Splitting to work with the two halves separately
    midpoint = int(len(roundInputValue) / 2)
    left = roundInputValue[:midpoint]
    right = roundInputValue[midpoint:]
    # Expanding right half
    rbin = bin(int(right, 16))[2:].zfill(32)
    expansio4ox = expansio4ox - 1
    expandedr = ""
    for index in expansio4ox:
        bit = rbin[index]
        expandedr += bit
    expandedrhex = hex(int(expandedr, 2))[2:].upper().zfill(12)
    # Xoring right half with key
    xorhex = des_XOR(expandedrhex, roundKey)
    xorbin = bin(int(xorhex, 16))[2:].zfill(48)
    # Now going thorugh 8 s boxes
    sbox_output = ""
    for i in range(8):
        segment = xorbin[i * 6 : (i + 1) * 6]
        row = int(segment[0] + segment[-1], 2)
        col = int(segment[1:5], 2)
        sboxval = sBoxes[i][row][col]
        sbox_output += bin(sboxval)[2:].zfill(4)

    permutebin = ""
    # Applying the final permutation
    for position in permutationChoice:
        select = sbox_output[position - 1]
        permutebin += select
    permutedhex = hex(int(permutebin, 2))[2:].upper().zfill(8)
    # Xor again with the original left half
    new_right = des_XOR(left, permutedhex)

    new_left = right

    return new_left + new_right


def des_Preprocess_Image_Plaintext(plaintext: np.ndarray) -> np.ndarray:  # 9
    plaintextt = plaintext.flatten()
    # Very similar to all the other preprocesses
    plaintextt = list(plaintextt)

    clen = len(plaintextt)
    remainder = clen % 8
    if remainder == 0:
        padlen = 8
    else:
        padlen = 8 - remainder

    for i in range(padlen):
        plaintextt.append(padlen)

    hex_array = []
    for value in plaintextt:
        hex_string = format(value, "02X")
        hex_array.append(hex_string)

    return np.array(hex_array)


def des_Remove_Image_Padding(paddedArray: np.ndarray) -> np.ndarray:  # 10
    # Same as all the other removes
    # paddedArray = paddedArray.astype(str)
    totallen = len(paddedArray)
    lastindex = totallen - 1
    padding = int(paddedArray[lastindex], 16)

    newleng = totallen - padding

    unpadded = []
    for i in range(newleng):
        unpadded.append(int(paddedArray[i], 16))

    return np.array(unpadded)


def des_Encrypt_Image(plaintext: np.ndarray, key: str) -> np.ndarray:  # 11
    keyPermChoice1 = np.load("DES_Arrays\\DES_Key_Permutation_Choice_1.npy")
    keyPermChoice2 = np.load("DES_Arrays\\DES_Key_Permutation_Choice_2.npy")
    keyRoundShifts = np.load("DES_Arrays\\DES_Round_Shifts.npy")
    sBoxes = np.load("DES_Arrays\\DES_sBoxes.npy")
    Fexpansio4ox = np.load("DES_Arrays\\DES_Expansion_Box.npy")
    FpermutationChoice = np.load("DES_Arrays\\DES_F_Function_Permutation.npy")
    initPerm = np.load("DES_Arrays\\DES_Initial_Permutation.npy")
    invInitPerm = np.load("DES_Arrays\\DES_Inverse_Initial_Permutation.npy")
    # The same as the encrypt string the the peprocess image
    cipher = []

    keys = des_Generate_Round_Keys(key, keyPermChoice1, keyPermChoice2, keyRoundShifts)
    plaintextpad = des_Preprocess_Image_Plaintext(plaintext)
    blocks = des_Create_Input_Blocks(plaintextpad)

    for block in blocks:
        blockhex = "".join(b.upper() for b in block)
        cipherresult = des_Process_Block(
            blockhex,
            keys,
            initPerm,
            sBoxes,
            Fexpansio4ox,
            FpermutationChoice,
            invInitPerm,
        )

        for i in range(0, len(cipherresult), 2):
            cipher.append(int(cipherresult[i : i + 2], 16))

    return np.array(cipher)


def des_Decrypt_Image(ciphertext: np.ndarray, key: str) -> np.ndarray:  # 12
    keyPermChoice1 = np.load("DES_Arrays\\DES_Key_Permutation_Choice_1.npy")
    keyPermChoice2 = np.load("DES_Arrays\\DES_Key_Permutation_Choice_2.npy")
    keyRoundShifts = np.load("DES_Arrays\\DES_Round_Shifts.npy")
    sBoxes = np.load("DES_Arrays\\DES_sBoxes.npy")
    Fexpansio4ox = np.load("DES_Arrays\\DES_Expansion_Box.npy")
    FpermutationChoice = np.load("DES_Arrays\\DES_F_Function_Permutation.npy")
    initPerm = np.load("DES_Arrays\\DES_Initial_Permutation.npy")
    invInitPerm = np.load("DES_Arrays\\DES_Inverse_Initial_Permutation.npy")
    # Same as the decrypt string withouth the turning it into a string
    plaintext = []
    decryoted = []

    keys = des_Generate_Round_Keys(key, keyPermChoice1, keyPermChoice2, keyRoundShifts)
    keys = keys[::-1]

    cthex = [hex(b)[2:].upper().zfill(2) for b in ciphertext]
    blocks = des_Create_Input_Blocks(cthex)

    for block in blocks:
        blockhex = "".join(b.upper() for b in block)

        plaint = des_Process_Block(
            blockhex,
            keys,
            initPerm,
            sBoxes,
            Fexpansio4ox,
            FpermutationChoice,
            invInitPerm,
        )

        for i in range(0, len(plaint), 2):
            decryoted.append(plaint[i : i + 2])
    unpadded = des_Remove_Image_Padding(np.array(decryoted))

    return np.array(unpadded)


def des_Apply_Permutation(
    valueToPermute: str, permuteTable: np.ndarray, numBitsBeforePermute: int
) -> str:  # 13
    # Converting to binary for permutation
    binval = bin(int(valueToPermute, 16))[2:].zfill(numBitsBeforePermute)
    # Minusing for the indexes to match
    permuteTable = permuteTable - 1
    select = []
    # Getting the permuation values
    for index in permuteTable:
        select.append(binval[index])
    permutedbin = "".join(select)
    # Turning it back into hex values
    permutedint = int(permutedbin, 2)
    permutedhex = hex(permutedint)[2:].upper()
    # Since hex digit is 4 bits
    hexlen = int(len(permutedbin) / 4)
    permutedhex = permutedhex.zfill(hexlen)
    return permutedhex


def des_Split_In_Two(inputValue: str) -> np.ndarray:  # 14
    mid = int(len(inputValue) / 2)
    left = inputValue[:mid]
    right = inputValue[mid:]
    return np.array([left, right])


def des_XOR(value1: str, value2: str) -> str:  # 15
    int1 = int(value1, 16)
    int2 = int(value2, 16)
    xor = int1 ^ int2
    return hex(xor)[2:].upper().zfill(len(value1))


def des_left_Shift(inputValue: str, shiftCount: int) -> str:  # 16
    # Total number of buys where each hex digit is 4 bits so multiply with 4
    leng = len(inputValue) * 4
    # Turning into binary for shifting
    binval = bin(int(inputValue, 16))[2:].zfill(leng)

    shifted = binval[shiftCount:] + binval[:shiftCount]

    shiftedhex = hex(int(shifted, 2))[2:].upper().zfill(len(inputValue))

    return shiftedhex


# key = "gktymbcn"
# cipher_hex = "yaniyaniyanikaralucindalucinda"

# result = des_Encrypt_String(cipher_hex, key)
# decrypt = des_Decrypt_String(result, key)
# print(result)
# print(decrypt)

# Dummy small image for testing (e.g., 2x2 image with 3 color channels RGB)
# test_img = np.random.randint(0, 256, size=(2, 2, 3), dtype=np.uint8)
# key = "MyDESKey"  # 8 characters for DES

# print("Original Test Image:")
# print(test_img)

# # Encrypt the image
# ciphertext = des_Encrypt_Image(test_img, key)
# print("\nCiphertext:")
# print(ciphertext)

# # Decrypt the image
# decrypted_flat = des_Decrypt_Image(ciphertext, key)

# # Use your function to convert it back into the image
# decrypted_img = aes_des_rc4_Convert_To_Image(decrypted_flat, test_img.shape)

# print("\nDecrypted Test Image:")
# print(decrypted_img)

# # Check if original and decrypted images match
# if np.array_equal(test_img, decrypted_img):
#     print("\n✅ DES Encryption-Decryption successful! Images match.")
# else:
#     print("\n❌ DES Decryption failed. Images do not match.")


# ----------------------------------------------------------------------------------------------
# RC4 Stream Cipher
# ----------------------------------------------------------------------------------------------


def rc4_Init_S_T(key: str) -> np.ndarray:  # 1
    S = []
    T = []
    # Getting the ascii characters
    keys = []
    for c in key:
        ascii = ord(c)
        keys.append(ascii)

    leng = len(keys)

    for i in range(256):
        S.append(i)
        T.append(keys[i % leng])

    return np.array([S, T])


def rc4_Init_Permute_S(sArray: np.ndarray, tArray: np.ndarray) -> np.ndarray:
    S = []
    for i in range(len(sArray)):
        S.append(sArray[i])
    j = 0
    for i in range(256):
        j = (j + S[i] + tArray[i]) % 256
        # Swapping the values
        S[i], S[j] = S[j], S[i]
    return np.array(S)


def rc4_Generate_Stream_Iteration(i: int, j: int, sArray: np.ndarray) -> tuple:  # 3

    i = (i + 1) % 256
    j = (j + sArray[i]) % 256
    sArray[i], sArray[j] = sArray[j], sArray[i]
    t = (sArray[i] + sArray[j]) % 256
    k = sArray[t]
    return (i, j, sArray, k)


def rc4_Process_Byte(byteToProcess: int, k: int) -> int:  # 4
    xor = byteToProcess ^ k
    return xor


def rc4_Encrypt_String(plaintext: str, key: str) -> np.ndarray:  # 5
    ST = rc4_Init_S_T(key)
    S = rc4_Init_Permute_S(ST[0], ST[1])

    i = 0
    j = 0
    result = []

    for char in plaintext:
        i, j, S, k = rc4_Generate_Stream_Iteration(i, j, S)
        encrypted = rc4_Process_Byte(ord(char), k)
        result.append(encrypted)
    return np.array(result)


def rc4_Decrypt_String(ciphertext: np.ndarray, key: str) -> str:  # 6

    ST = rc4_Init_S_T(key)
    S = rc4_Init_Permute_S(ST[0], ST[1])

    i = 0
    j = 0
    plaintext_chars = []

    for byte in ciphertext:
        i, j, S, k = rc4_Generate_Stream_Iteration(i, j, S)
        decrypted_byte = rc4_Process_Byte(byte, k)
        plaintext_chars.append(chr(decrypted_byte))

    return "".join(plaintext_chars)


def rc4_Encrypt_Image(plaintext: np.ndarray, key: str) -> np.ndarray:  # 7
    flat_data = plaintext.flatten()
    ST = rc4_Init_S_T(key)
    S = rc4_Init_Permute_S(ST[0], ST[1])
    i = 0
    j = 0
    encrypted = []
    for byte in flat_data:
        i, j, S, k = rc4_Generate_Stream_Iteration(i, j, S)
        encrypted_byte = rc4_Process_Byte(int(byte), k)
        encrypted.append(encrypted_byte)

    return np.array(encrypted)


def rc4_Decrypt_Image(ciphertext: np.ndarray, key: str) -> np.ndarray:  # 8
    ST = rc4_Init_S_T(key)
    S = rc4_Init_Permute_S(ST[0], ST[1])
    i = 0
    j = 0

    decrypted = []
    for byte in ciphertext:
        i, j, S, k = rc4_Generate_Stream_Iteration(i, j, S)
        decrypted_byte = rc4_Process_Byte(int(byte), k)
        decrypted.append(decrypted_byte)

    return np.array(decrypted)


# key = "fktjrmvndjslrny"
# cipher_hex = "hallohalloogod"

# result = rc4_Encrypt_String(cipher_hex, key)
# decrypt = rc4_Decrypt_String(result, key)
# result_hex = [hex(num)[2:].upper().zfill(2) for num in result]
# print(result_hex)
# print(decrypt)

# test_img = np.random.randint(0, 256, size=(2, 2, 3), dtype=np.uint8)
# key = "MyRC4Key"  # Key can be any length

# print("Original Test Image:")
# print(test_img)

# # Encrypt the image
# ciphertext = rc4_Encrypt_Image(test_img, key)
# print("\nCiphertext:")
# print(ciphertext)

# # Decrypt the image
# decrypted_flat = rc4_Decrypt_Image(ciphertext, key)

# # Rebuild the image using your conversion function
# decrypted_img = aes_des_rc4_Convert_To_Image(decrypted_flat, test_img.shape)

# print("\nDecrypted Test Image:")
# print(decrypted_img)

# # Check if original and decrypted images match
# if np.array_equal(test_img, decrypted_img):
#     print("\n✅ RC4 Encryption-Decryption successful! Images match.")
# else:
#     print("\n❌ RC4 Decryption failed. Images do not match.")

# ----------------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------------
