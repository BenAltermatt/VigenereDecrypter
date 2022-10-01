import numpy as np  # vectorization will make our operations a lil faster
import warnings
warnings.filterwarnings('ignore')

import sys # I want to handle the command line arguments

# here are some constants we are just going to define here for the sake of 
# time. It's a little gross looking to do this in the code but let's not worry about it too much haha.
p = np.array([.08167, .01492, .02782, .04253, .12702, .0228, .02105, .06094,
    .06966, .00153, .00772, .04025, .02406, .06749, .07507, .01929, .00095,
    .05987, .06327, .09056, .02758, .00978, .0236, .0015, .01974, .00074])


# this counts the frequency of 
# each letter in a string and returns 
# a frequency vector
def freq_vec(string):
    freqs = [0] * 26

    string = string.upper()

    for c in string:
        freqs[ord(c) - 65] += 1

    return np.array(freqs)

# the goal of this method is to calculate
# the index of coincidence for a single 
# string
def index_c(string):
    freqs =  freq_vec(string)  # the number of appearances each character, indexed by A = 0, B = 1, etc.

    coin_c  = 0 # our number of coincidences
    # now we need to sum up all of the probabilities
    # of selecting two of a given letter from the string
    for i in range(len(freqs)):
        coin_c += freqs[i] * (freqs[i] - 1) # add the probability of drawing each letter individually

    return coin_c / len(string) /  (len(string) - 1) # this is our index of coincidence for this string.
        

# this makes substrings for m and then
# calculates the distance of the index of
# coincidence for each string from the ideal of 
# .065, summing and returning a total error for m
def m_error(string, m, verbose=False):
    # first, we must build the substrings

    substrs = [''] * m # m substrings
    for ind in range(len(string)):
        # we will add to each substring by the 
        # modulus of the index to m

        substrs[ind % m] += (string[ind])

    # now that we have built them, we must add
    # their errors to the total error
    total_error = 0

    for ind in range(len(substrs)):
        substr = substrs[ind]

        error = .065 - index_c(substr)

        if verbose:
            print('\ty{:d} is {:s}\n\tand has an index of coincidence of {:f}'.format(ind, substr, index_c(substr)))

        if error < 0:
            total_error += error * -1
        else:
            total_error += error

    return total_error / m

# this method is responsible for finding 
# the most likely key length given the key lengths 
# we would like to check and ciphertext
def choose_m(string, mrange=None, verbose=False):
    if not mrange:
        max_m = len(string)
        min_m = 0
    else:
        max_m = mrange[1]
        min_m = mrange[0]

    minError = -1
    best_m = None
    
    # try and compare the error for each m
    for m in range(min_m, max_m + 1):
        error = m_error(string, m, verbose)

        if verbose:
            print('Average \'error\' for m of {:d} was {:f}'.format(m, error))

        if minError == -1 or minError > error:
            minError = error
            best_m = m

    return best_m


def build_table(mgsmatrix):
    output = '|g\t|'
    for i in range(len(mgsmatrix)):
        output += "M{:d}\t|".format(i + 1)
    
    output += '\n'

    for i in range(0, 26):
        output += '|{:d}\t|'.format(i)
        for j in range(len(mgsmatrix)):
            output += '{:.2f}\t|'.format(mgsmatrix[j][i] * 100)
        output += '\n'
    
    return output

# most likely key
def likely_key(string, m, verbose=False):
    g_prods = list() # this is the list of dot products between the offset messages and p
    y = [''] * m

    # I need to build the y_i strings
    for i in range(len(string)):
        y[i % m] += string[i] 

    # now we will build our q vectors for each y
    qs = list()
    for yi in y:
        qs.append(freq_vec(yi) / len(yi))

    mgmat = list()
    # now for every value of g, we need to roll through each value in 
    # each y and get the top dot products
    for q in qs:
        mgs = list()
        for g in range(0, 26):
            mg = np.dot(np.roll(q, -g), p)

            mgs.append(mg)
        
        mgmat.append(np.array(mgs))

    # the mgs should be offsets we can associate with letters
    key = ''
    for g in mgmat:
        key += chr(65 + g.argmax())

    if verbose:
        print(build_table(mgmat))

    return key.lower()


# this will decrypt a message into plaintext
def decrypt(string, key=None, verbose=False, mrange=None):

    if verbose:
        print(string)

    # if the key is none we have to run through and print out 
    if not key:
        print('No key passed. Performing ciphertext only attack. (One attempt)')
        # we need to figure out m
        m = choose_m(string, mrange, verbose)
        key = likely_key(string, m, verbose)
        print('Found most likely key: {:s}'.format(key))
    
    # now the simple actual decryption
    ct = string.upper() # our ciphertext
    pt = '' # the plaintext we want
    for ind in range(len(ct)):
        pt += chr(((ord(ct[ind]) - 65) - (ord(key[ind % m]) - 97))% 26 + 97)
    
    return pt


# now just some stuff to handle inputs and make everything run a little smoother
args = set(sys.argv)

# -v for verbose generation
# -r for the range of ms
# -k for key use

filename = sys.argv[1]
ct = ''

# make our cipher text from our file
with open(filename, 'rt') as file:
    for line in file.readlines():
        puretext = line.split()
        for val in puretext:
            ct += val

verbose = '-v' in args
mrange = (1, len(ct))

if '-r' in args:
    ind = 1
    while sys.argv[ind] != '-r':
        ind += 1
    
    mrange = (int(sys.argv[ind + 1]), int(sys.argv[ind + 2]))

key = None
if '-k' in args:
    ind = 1
    while sys.argv[ind] != '-k':
        ind += 1
    
    key = (sys.argv[ind + 1])

print(decrypt(ct, key, verbose, mrange))
