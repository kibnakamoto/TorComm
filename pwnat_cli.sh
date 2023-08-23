. ./configure.sh

sudo ./pwnat/pwnat -c $PRIVATE $PORT $PUBLIC_B $PORT $MSG

# sudo ./pwnat/pwnat -c 8000 127.0.0.1 
# sudo ./pwnat/pwnat -s 8000


# send ssh UDP packet on which server?
# sudo ssh -p 8000 127.0.0.1 ""
