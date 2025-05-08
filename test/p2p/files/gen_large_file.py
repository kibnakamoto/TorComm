# Generate large file with random data, for sending large data unit tests

import os

# file size at least 2**28
size_bytes = 2**28 + 1234
with open("large_file.txt", 'wb') as f:
    f.write(os.urandom(size_bytes))
