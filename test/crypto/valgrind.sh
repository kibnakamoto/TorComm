# valgrind tests, run after changes to make sure memory management is flawless

valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes -s ./crypto
