#!/bin/bash

# Imtiaz
python2.7 setup.py build
sudo python2.7 setup.py install
echo "Copying to specific folder"
cp dist/BLESMPServer-1.0.1-py2.7-linux-x86_64.egg ../../venv/lib/python2.7/site-packages

#~/anaconda3/envs/py2/bin/python setup.py build
#sudo ~/anaconda3/envs/py2/bin/python setup.py install
#echo "Copying to specific folder"
#cp dist/BLESMPServer-1.0.1-py2.7-linux-x86_64.egg ~/anaconda3/envs/py2/lib/python2.7/site-packages
