# SSHoney - A SSH Honeypot 🍯 written in C

A C based honeypot that captures SSH connections and alerts the host that someone tried to access the server, and what commands they tried to run. 

## Requirements

To run this program, make sure you have the following libraries installed:   

- stdio.h
- stdlib.h
- string.h
- assert.h
- unistd.h
- sys/types.h
- sys/socket.h
- netinet/in.h
- time.h    

These libraries are commonly included in most C compilers and development environments.

## Usage 🐝🐝🐝

To compile the program, run: `gcc SSHoney.c -ansi -Wall -o SSHoney`    

To change the port: type `./SSHoney -p PORT` and replace `PORT` with the port you want to run the program on. By default, the program will run on port 22.   

To change the log's name: type `./SSHoney -o NAME` and replace `NAME` with the name of the log file. By default the log will be called log.txt. SSHoneypot will never overwrite log data and will append data to the log. 

Run `./SSHoney -h` for help information.    

## License

The MIT License (MIT)

Copyright (c) 2023 Thomas Jordan

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.