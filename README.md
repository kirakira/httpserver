Introduction
============
A simple web server written in pure C capable of serving static objects and php scripts.

This was a course project of Computer Networks.


Usage
=====

httpserver [-p PORT] [-d ROOT_DIR] [-b BACKLOG]
Run a simple HTTP server.

PORT - Listen port. Default 8080.
ROOT_DIR - Server root directory. Default current working directory.
BACKLOG - Maximum outstanding connections. Defualt 5.
