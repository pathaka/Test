#!/usr/bin/env sh
rm ms.txt google.txt iit.txt

function ms()
{
    for i in `seq 1 1 5`; do 
	echo ms $i
	./pathneck -c -i 128.46.101.59 202.3.77.184 >> ms.txt  
    done
}

function google(){
    for i in `seq 1 1 5`; do 
	echo google $i
	./pathneck -c -i 128.46.101.59 72.14.204.99 >> google.txt
    done
}

function iit(){
    for i in `seq 1 1 5`; do 
	echo iit $i
	./pathneck -c -i 128.46.101.59 202.3.77.184 >> iit.txt
    done
}


(eval ms )
(eval iit )
google