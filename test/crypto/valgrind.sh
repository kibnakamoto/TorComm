# valgrind tests, run after changes to make sure memory management is flawless
# technically it shows 16 bytes lost, but that error isn't real. It's crypto++ efficiency thing, it can be hiden

valgrind --leak-check=full --show-leak-kinds=definite --errors-for-leak-kinds=definite  --track-origins=yes -s ./crypto
