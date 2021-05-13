#!/bin/bash

shopt -s expand_aliases

alias python='python3.1'

clear
echo "Results script executing"

#echo "Unbounded HIBE Rouselakis - Waters ..."
#echo "Unbounded HIBE Rouselakis - Waters ..." > /home/yannis/Desktop/results.txt
#python uhibe_rw12.py >> /home/yannis/Desktop/results.txt

echo "Unbounded KPABE Rouselakis - Waters ..."
echo "Unbounded KPABE Rouselakis - Waters ..." > /home/yannis/Desktop/results.txt
python ukpabe_rw12.py >> /home/yannis/Desktop/results.txt

echo "Unbounded CPABE Rouselakis - Waters ..."
echo "Unbounded CPABE Rouselakis - Waters ..." >> /home/yannis/Desktop/results.txt
python ucpabe_rw12.py >> /home/yannis/Desktop/results.txt

#echo "Unbounded HIBE Lewko ..."
#echo "Unbounded HIBE Lewko ..." >> /home/yannis/Desktop/results.txt
#python uhibe_l12.py >> /home/yannis/Desktop/results.txt

echo "Unbounded KPABE Lewko ..."
echo "Unbounded KPABE Lewko ..." >> /home/yannis/Desktop/results.txt
python ukpabe_l12.py >> /home/yannis/Desktop/results.txt

exit 0
