# valgrind tests, run after changes to make sure memory management is flawless

valgrind --leak-check=full --show-leak-kinds=definite --errors-for-leak-kinds=definite --track-origins=yes -s ./p2p
