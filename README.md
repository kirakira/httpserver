Introduction
============
A simple web server written in pure C capable of serving static objects and php scripts.

This was a course project of Computer Networks.


Usage
=====

`httpserver [-p PORT] [-d ROOT_DIR] [-b BACKLOG]`

*  PORT - Listen port. Default 8080.
*  ROOT\_DIR - Server root directory. Default current working directory.
*  BACKLOG - Maximum outstanding connections. Defualt 5.


Build
=====

`make`

Compiling the source requires linux and gcc.
php-cgi is not requied to compile, but you may need it to server php pages.
