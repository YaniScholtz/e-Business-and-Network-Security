# Name: Yani Scholtz
# Student num: 22510657

"""
IMPORTANT!!

- Due 13 March 2024 (before 8h30)
- No late submissions (AMS and Turnitin) accepted after 8h30!
- The prac test starts at 10h30 in the Netlabs.

- Rename this file to "<YourStudentNumber>_Prac_1.py", for example: "19056789_Prac_1.py"
- Comment your code (follow best practice)
- Submit .py to AMS and a .pdf to ClickUp (TurnItIn)
- Also, please upload your turnitin receipt to the AMS.
- Remove all print statements - and helper functions (that weren't provided) - used for unit testing.

- Please read the practical guide for instructions!
"""

import string
import numpy as np


# 3.1 Playfair Cipher
# ----------------------------------------------------------------------------------------------------


def playfair_get_key(isText: bool, key: str) -> np.ndarray:  # 3.1.1
    if isText:

        # String handling removing of j, removing any special characters and lowercase
        key = key.replace("j", "i")
        key = "".join([char for char in key if char.isalpha()])
        key = key.lower()
        # checking for duplicates using a set
        seen = set()
        processedkey = []
        for char in key:
            if char not in seen:
                seen.add(char)
                processedkey.append(char)
        # adding the remaining aplaphet
        alphabet = "abcdefghiklmnopqrstuvwxyz"
        for char in alphabet:

            if char not in seen:
                processedkey.append(char)
        matrix_rows = []

        # making the 5x5 matrix
        for i in range(0, len(processedkey), 5):
            row = processedkey[i : i + 5]
            matrix_rows.append(row)

        matrix = np.array(matrix_rows)
    else:
        # doing the same for a image
        seen = set()
        processedkey = []
        for char in key:
            ascii_val = ord(char)
            if ascii_val not in seen:
                seen.add(ascii_val)
                processedkey.append(char)

        # getting the ascii values of the chars
        ascii_values = [ord(char) for char in processedkey]
        missing_numbers = []

        for num in range(256):
            if num not in seen:
                missing_numbers.append(num)

        full_key = ascii_values + missing_numbers

        first_256_elements = full_key[:256]

        matrix = np.array(first_256_elements)

        matrix = matrix.reshape(16, 16)

    return matrix


def playfair_get_pos_in_key(val, val2, keyMat: np.ndarray) -> np.ndarray:  # 3.1.2
    valPositions = []
    rows, cols = keyMat.shape
    # finding positions of the parameters through a for loop

    for row in range(rows):
        for col in range(cols):
            if keyMat[row][col] == val:
                valPositions.append(row)
                valPositions.append(col)

    for row in range(rows):
        for col in range(cols):
            if keyMat[row][col] == val2:
                valPositions.append(row)
                valPositions.append(col)

    return np.array(valPositions)


def playfair_get_encryption_pos(
    pos: np.ndarray, keyMat: np.ndarray
) -> np.ndarray:  # 3.1.3

    r1, c1, r2, c2 = pos
    mod_val = len(keyMat)
    nr1 = nr2 = nc1 = nc2 = None

    # if the rows are the same, then the items must move down in the column
    if r1 == r2:
        nc1 = (c1 + 1) % mod_val
        nc2 = (c2 + 1) % mod_val
        nr1 = r1
        nr2 = r2
    # if the cols are the same then the items must move to the right
    elif c1 == c2:
        nc1 = c1
        nc2 = c2
        nr1 = (r1 + 1) % mod_val
        nr2 = (r2 + 1) % mod_val
    # move the items to the opposite end of the triangle
    else:
        nr1 = r1
        nc1, nc2 = c2, c1
        nr2 = r2

    return np.array([nr1, nc1, nr2, nc2])


def playfair_get_decryption_pos(
    pos: np.ndarray, keyMat: np.ndarray
) -> np.ndarray:  # 3.1.4
    r1, c1, r2, c2 = pos
    mod_val = len(keyMat)
    nr1 = nr2 = nc1 = nc2 = None
    # if the rows are the same then move the values up in the row
    if r1 == r2:
        nc1 = (c1 + mod_val - 1) % mod_val
        nc2 = (c2 + mod_val - 1) % mod_val
        nr1 = r1
        nr2 = r2
    # if the cols are the same then move the items to the left
    elif c1 == c2:
        nc1 = c1
        nc2 = c2
        nr1 = (r1 + mod_val - 1) % mod_val
        nr2 = (r2 + mod_val - 1) % mod_val
    # Move the items to the opposite side of the rectangle
    else:
        nr1 = r1
        nc1, nc2 = c2, c1
        nr2 = r2

    return np.array([nr1, nc1, nr2, nc2])


def playfair_preprocess_text(plaintext: str) -> str:  # 3.1.5
    # Must I remove the spaces as well?
    plaintext = plaintext.lower()
    plaintext = "".join([char for char in plaintext if char.isalpha()])
    plaintext = plaintext.replace("j", "i")

    preprocesstext = ""
    i = 0
    while i < len(plaintext):
        if i == len(plaintext) - 1:
            preprocesstext += plaintext[i] + "x"  # missing pair at the end
            break
        elif (
            plaintext[i] == plaintext[i + 1]
        ):  # adding filler if there are identical characters next to each other
            preprocesstext += plaintext[i] + "x"
            i += 1
        else:
            preprocesstext += (
                plaintext[i] + plaintext[i + 1]
            )  # otherwise add the two characters to the processed text
            i += 2

    if (
        len(preprocesstext) % 2 != 0
    ):  # making sure there are even pairs by adding padding
        preprocesstext += "x"
    return preprocesstext


def playfair_encrypt_text(plaintext: str, key: str) -> str:  # 3.1.6
    preprocessed_text = playfair_preprocess_text(plaintext)

    key_matrix = playfair_get_key(True, key)

    encrypted_text = ""
    for i in range(
        0, len(preprocessed_text), 2
    ):  # playfair algorithm works in pairs so  for loop that jumps in twos
        char1, char2 = preprocessed_text[i], preprocessed_text[i + 1]

        valuepositions = playfair_get_pos_in_key(char1, char2, key_matrix)

        new_pos = playfair_get_encryption_pos(valuepositions, key_matrix)

        encrypted_text = encrypted_text + key_matrix[new_pos[0], new_pos[1]]
        encrypted_text = encrypted_text + key_matrix[new_pos[2], new_pos[3]]

    return encrypted_text


def playfair_decrypt_text(ciphertext: str, key: str) -> str:  # 3.1.7
    key_matrix = playfair_get_key(True, key)

    decrypted_text = ""
    for i in range(0, len(ciphertext), 2):
        char1, char2 = ciphertext[i], ciphertext[i + 1]

        valuepositions = playfair_get_pos_in_key(char1, char2, key_matrix)

        new_pos = playfair_get_decryption_pos(valuepositions, key_matrix)

        decrypted_text = decrypted_text + key_matrix[new_pos[0], new_pos[1]]
        decrypted_text = decrypted_text + key_matrix[new_pos[2], new_pos[3]]
        # Algorithm is the same as the encryption except for the next part that removes padding and filler
    final = ""
    for i in range(len(decrypted_text)):
        # checking for if there is an x in the string
        if decrypted_text[i] == "x":
            if (
                # take away the string if it is inbetween identical values
                i > 0
                and i < len(decrypted_text) - 1
                and decrypted_text[i - 1] == decrypted_text[i + 1]
            ):
                continue
            if i == len(decrypted_text) - 1:
                continue

        final += decrypted_text[i]

    return final


def playfair_preprocess_image(plaintext: np.ndarray) -> np.ndarray:  # 3.1.8
    oneD_array = plaintext.flatten()

    for i in range(len(oneD_array)):
        if oneD_array[i] == 129:
            oneD_array[i] = 128

    index = 0
    newplaintext = []
    length = len(oneD_array)
    # again adding filler and padding values

    while index < length - 1:
        if (
            oneD_array[index] == oneD_array[index + 1]
        ):  # two identical characters must have a filler in between
            newplaintext.append(oneD_array[index])
            newplaintext.append(129)
            index += 1
        else:
            newplaintext.append(
                oneD_array[index]
            )  # adding both characters if they are not identical
            newplaintext.append(oneD_array[index + 1])
            index += 2

    if (
        index == length - 1
    ):  # add padding if there is an unequal amount and does not make pairs
        newplaintext.append(oneD_array[index])
        newplaintext.append(129)
    return np.array(newplaintext)


def playfair_remove_image_padding(
    plaintextWithPadding: np.ndarray,
) -> np.ndarray:  # 3.1.9

    plaintext_original = []
    for i in plaintextWithPadding:
        if i != 129:
            plaintext_original += [i]

    return np.array(plaintext_original)


def playfair_encrypt_image(plaintext: np.ndarray, key: str) -> np.ndarray:  # 3.1.10
    matrix = playfair_get_key(False, key)
    plaintext_process = playfair_preprocess_image(plaintext)
    # similar algorithm as the text except it works with arrays and not string

    encrypted_text = []
    new_pos = []
    for i in range(0, len(plaintext_process), 2):
        char1, char2 = plaintext_process[i], plaintext_process[i + 1]

        valuepositions = playfair_get_pos_in_key(char1, char2, matrix)

        new_pos += [playfair_get_encryption_pos(valuepositions, matrix)]

    for i in new_pos:
        encrypted_text += [matrix[i[0], i[1]]] + [matrix[i[2], i[3]]]

    return np.array(encrypted_text)


def playfair_decrypt_image(
    removePadding: bool, ciphertext: np.ndarray, key: str
) -> np.ndarray:  # 3.1.11
    matrix = playfair_get_key(False, key)

    decrypted = []
    final = []
    new_pos = []

    for i in range(0, len(ciphertext), 2):
        char1, char2 = ciphertext[i], ciphertext[i + 1]

        valuepositions = playfair_get_pos_in_key(char1, char2, matrix)

        new_pos += [playfair_get_decryption_pos(valuepositions, matrix)]

    final = []

    for i in new_pos:
        final += [matrix[i[0], i[1]]] + [matrix[i[2], i[3]]]

    # removing the padding if it needs to be removed

    if removePadding:
        return np.array(playfair_remove_image_padding(final))
    else:
        return np.array(final)


def playfair_convert_to_image(
    imageData: np.ndarray, originalShape
) -> np.ndarray:  # 3.1.12

    total_pixels = originalShape[0] * originalShape[1] * originalShape[2]
    data_len = len(imageData)

    new_image_data = list(imageData)

    if data_len < total_pixels:
        new_image_data.extend([129] * (total_pixels - data_len))

    image_array = np.array(new_image_data, dtype=np.uint8).reshape(originalShape)

    return np.array(image_array)


# ----------------------------------------------------------------------------------------------------

# 3.2 Hill Cipher
# ----------------------------------------------------------------------------------------------------


def hill_get_key(isText: bool, key: str) -> np.ndarray:  # 3.2.1
    if isText:
        # string handling

        key = "".join(char for char in key if char.isalpha())
        key = key.lower()

        if len(key) != 4 and len(key) != 9:
            return np.array([-1])

        if len(key) == 9:
            # creating a base array
            matrix = [[0] * 3 for i in range(3)]
            k = 0
            size = 3
            for i in range(3):
                for j in range(3):
                    # adding the asci  to the matrix
                    matrix[i][j] = ord(key[k]) - 97
                    k += 1
        else:
            # same for if the key length is 4
            matrix = [[0] * 2 for i in range(2)]
            k = 0
            size = 2
            for i in range(2):
                for j in range(2):
                    # adding the ascii to the matrix
                    matrix[i][j] = ord(key[k]) - 97
                    k += 1

        determinate = int(np.round(np.linalg.det(matrix)))
        # euclidean algorithm to see if det us coprime with 26
        a, b = determinate, 26

        while b:
            # getting the gcd
            a, b = b, a % b

        # returning if it does not meet the criteria
        if determinate % 26 == 0 or a != 1:
            return np.full((size, size), -1)
    else:
        # same algorithm as above but using the modulus amount of 256

        if len(key) != 4 and len(key) != 9:
            return np.array([-1])

        if len(key) == 9:
            matrix = [[0] * 3 for i in range(3)]
            k = 0
            size = 3
            for i in range(3):
                for j in range(3):
                    matrix[i][j] = ord(key[k])
                    k += 1
        else:

            matrix = [[0] * 2 for i in range(2)]
            k = 0
            size = 2
            for i in range(2):
                for j in range(2):
                    matrix[i][j] = ord(key[k])
                    k += 1

        determinate = int(np.round(np.linalg.det(matrix)))

        a, b = determinate, 256

        while b:
            a, b = b, a % b

        if determinate % 256 == 0 or a != 1:
            return np.full((size, size), -1)

    return np.array(matrix)


def hill_get_inv_key(isText: bool, keyMat: np.ndarray) -> np.ndarray:
    """Finds the inverse key for the Hill Cipher."""

    if isText:
        # getting the determiate
        det = int(round(np.linalg.det(keyMat))) % 26
        det = det % 26

        inv_det = None
        for i in range(1, 26):
            if (det * i) % 26 == 1:  # checking for multiplicative inverse
                inv_det = i
                break

        if inv_det is None:
            return np.full(keyMat.shape, -1)

        size = len(keyMat)
        cofactors = np.zeros_like(keyMat)

        for i in range(size):
            for j in range(size):
                # getting the minor matric by deleting the row and col
                minor = np.delete(np.delete(keyMat, i, axis=0), j, axis=1)
                # getting the determinate of minor and changing the sign according to the cofactor
                cofactors[i, j] = ((-1) ** (i + j)) * round(np.linalg.det(minor))

        join = np.transpose(cofactors)
        inv_key = (inv_det * join) % 26
    else:
        # same as above just using the value 256 for the images
        det = int(round(np.linalg.det(keyMat))) % 256
        det = det % 256

        inv_det = None
        for i in range(1, 256):
            if (det * i) % 256 == 1:
                inv_det = i
                break

        if inv_det is None:
            return np.full(keyMat.shape, -1)

        size = len(keyMat)
        cofactors = np.zeros_like(keyMat)

        for i in range(size):
            for j in range(size):
                minor = np.delete(np.delete(keyMat, i, axis=0), j, axis=1)
                cofactors[i, j] = ((-1) ** (i + j)) * round(np.linalg.det(minor))

        join = np.transpose(cofactors)
        inv_key = (inv_det * join) % 256

    return np.array(inv_key.astype(int))


def hill_process_group(
    isText: bool, text_vector: np.ndarray, keyMat: np.ndarray
) -> np.ndarray:
    keySize = keyMat.shape[0]

    # shaping to be able to matmul with the keymat
    group = text_vector.reshape(-1, keySize)

    if isText:
        # multiplyint the group with keymat
        result = (group @ keyMat) % 26
    else:
        result = (group @ keyMat) % 256

    return np.array(result.flatten())


def hill_pre_process_text(plaintext: str, keyLength: int) -> np.ndarray:  # 3.2.4
    # string handling
    plaintext = plaintext.lower()
    plaintext = "".join(char for char in plaintext if char.isalpha())

    plaintextarray = []
    for char in plaintext:
        # changing characters in numbers
        plaintextarray.append(ord(char) - 97)

    plaintextarray = np.array(plaintextarray)

    keySize = int(np.sqrt(keyLength))

    # getting amount of padding characters needed to add to the plaintext

    remainder = len(plaintextarray) % keySize

    if remainder != 0:
        padding_needed = keySize - remainder
    else:
        padding_needed = 0

    if padding_needed > 0:
        plaintextarray = np.append(plaintextarray, [23] * padding_needed)

    return np.array(plaintextarray)


def hill_encrypt_text(plaintext: str, key: str) -> str:  # 3.2.5
    keymat = hill_get_key(True, key)

    if (keymat[0][0]) == -1:
        return "Invalid Key"

    plain = hill_pre_process_text(plaintext, len(key))
    encrypted = hill_process_group(True, plain, keymat)
    encrypted_text = ""

    for i in encrypted:
        encrypted_text += chr(i + 97)

    return encrypted_text


def hill_decrypt_text(ciphertext: str, key: str) -> str:  # 3.2.6\
    # find key matrix
    keymat = hill_get_key(True, key)

    # checking if key is invertible
    if keymat[0][0] == -1:
        return "Invalid Key"

    inv_key = hill_get_inv_key(True, keymat)
    decrypt = hill_pre_process_text(ciphertext, len(inv_key))

    plain = hill_process_group(True, decrypt, inv_key)
    # going back to normal characters

    decrypted_text = ""
    for i in plain:
        decrypted_text += chr(i + 97)

    decrypted_text = decrypted_text.rstrip("x")

    return decrypted_text


def hill_pre_process_image(
    plaintext: np.ndarray, keyLength: int
) -> np.ndarray:  # 3.2.7
    if keyLength == 9:
        keySize = 3
    else:
        keySize = 2

    flattened = plaintext.flatten()
    listprocess = []

    # removing any 129 values
    for val in flattened:
        if val == 129:
            listprocess.append(128)
        else:
            listprocess.append(val)

    processarray = np.array(listprocess)

    remainder = len(processarray) % keySize
    # once again working out the number of padding values

    if remainder == 0:
        padding_needed = 0
    else:
        padding_needed = keySize - remainder

    if padding_needed > 0:
        padding_val = [129] * padding_needed
        for val in padding_val:
            processarray = np.append(processarray, val)

    return np.array(processarray)


def hill_encrypt_image(plaintext: np.ndarray, key: str) -> np.ndarray:  # 3.2.8
    keymat = hill_get_key(False, key)

    if keymat[0][0] == -1:
        return np.array([])

    encrypt = hill_pre_process_image(plaintext, len(key))

    encrypted = hill_process_group(False, encrypt, keymat)

    return np.array(encrypted)


def hill_decrypt_image(ciphertext: np.ndarray, key: str) -> np.ndarray:  # 3.2.9
    keymat = hill_get_key(False, key)

    if keymat[0][0] == -1:
        return np.array([])

    inv_key = hill_get_inv_key(False, keymat)

    if inv_key[0][0] == -1:
        return np.array([])

    key_size = inv_key.shape[0]

    decrypt = hill_process_group(False, ciphertext, inv_key)

    if decrypt is None:
        return np.array([])

    # removing padding values

    removedecrypt = []
    for i in decrypt:
        if i != 129:
            removedecrypt.append(i)

    return np.array(removedecrypt)


def hill_convert_to_image(imageData: np.ndarray, originalShape) -> np.ndarray:  # 3.2.10

    tot = 1
    for num in originalShape:
        tot *= num

    imageData = np.array(imageData, dtype=np.uint8)

    flattened_data = imageData.flatten()
    new_image_data = list(flattened_data)

    if len(new_image_data) < tot:
        padding_size = tot - len(new_image_data)
        padding_values = [129] * padding_size
        new_image_data.extend(padding_values)
    else:
        new_image_data = new_image_data[:tot]

    image_array = np.array(new_image_data, dtype=np.uint8)
    image = image_array.reshape(originalShape)

    return np.array(image)


# ----------------------------------------------------------------------------------------------------

# 3.3 Row Transposition Cipher
# ----------------------------------------------------------------------------------------------------


def row_gen_key(key: str) -> np.ndarray:  # 3.3.1

    seen = set()
    unique_key = ""

    # remove duplicates
    for char in key:
        if char not in seen:
            seen.add(char)
            unique_key += char

    ascii_list = []
    index = 0
    for char in unique_key:
        ascii_value = ord(char)
        # convert characters to asci and also store their original indices
        ascii_list.append((index, ascii_value))
        index += 1

    # sorting the asci values from smallest to biggest using a selection sort
    n = len(ascii_list)
    for i in range(n):
        min_index = i
        for j in range(i + 1, n):
            if ascii_list[j][1] < ascii_list[min_index][1]:
                min_index = j
        ascii_list[i], ascii_list[min_index] = ascii_list[min_index], ascii_list[i]

    # extract sorted indices from the the sorted ascii list
    sorted_indices = [index for index, i in ascii_list]
    # list to store the ranking poistions of the characters
    generated_key = []
    for i in range(len(unique_key)):
        rank = sorted_indices.index(i)
        generated_key.append(rank)

    newgen = []
    k = 0
    while k < len(generated_key):
        for i in range(len(generated_key)):
            if k == generated_key[i]:  # find corresponding to the current rank
                newgen.append(i)
                k += 1

    return np.array(newgen)


def row_pad_text(plaintext: str, key: np.ndarray) -> str:  # 3.3.2
    # getting number of cols in the key
    cols = len(key)

    plaintextlen = len(plaintext)

    plaintextlist = list(plaintext)
    # getting number of rows in the key
    rows = int(np.ceil(plaintextlen / cols))

    matrixcels = rows * cols
    paddingneeded = matrixcels - plaintextlen

    for i in range(paddingneeded):
        plaintextlist.append("x")

    text = "".join(plaintextlist)

    return text


def row_encrypt_single_stage(plaintext: str, key: np.ndarray) -> str:  # 3.3.3
    plaintextPadded = row_pad_text(plaintext, key)
    plaintextlist = list(plaintextPadded)
    encrypted = ""
    col = len(key)

    rows = int(np.ceil(len(plaintextlist) / col))
    matrix = []
    start = 0
    # creating the matrix
    for i in range(rows):
        row = plaintextlist[start : start + col]
        matrix.append(row)
        start += col
    # read the matrix column wise following the key
    encrypted = ""
    for col_index in key:
        for row in matrix:
            encrypted += row[col_index]

    return encrypted


def row_decrypt_single_stage(ciphertext: str, key: np.ndarray) -> str:  # 3.3.4
    row = int(np.ceil(len(ciphertext) / len(key)))
    col = len(key)

    # creating matrix
    matrix = [[""] * col for i in range(row)]

    # going back and populating the matrix in order of original matrix
    index = 0
    for col_index in key:
        for row_index in range(row):
            matrix[row_index][col_index] = ciphertext[index]
            index += 1

    # read the matric row for row and joining it in a string
    decrypted_text = "".join("".join(row) for row in matrix)

    return decrypted_text


def row_encrypt(plaintext: str, key: str, stage: int) -> str:  # 3.3.5
    key_array = row_gen_key(key)
    encrypted_text = row_encrypt_single_stage(plaintext, key_array)
    # if more encryption is needed
    if stage == 2:
        encrypted_text = row_encrypt_single_stage(encrypted_text, key_array)

    return encrypted_text


def row_decrypt(ciphertext: str, key: str, stage: int) -> str:  # 3.3.6
    key_array = row_gen_key(key)
    encrypted_text = row_decrypt_single_stage(ciphertext, key_array)
    # if more encryption is needed
    if stage == 2:
        encrypted_text = row_decrypt_single_stage(encrypted_text, key_array)

    encrypted_text = encrypted_text.strip("x")

    return encrypted_text


# ----------------------------------------------------------------------------------------------------
