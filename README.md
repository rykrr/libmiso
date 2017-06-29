# libmiso: Minimal Socket Wrapper
Create TLS server and client sockets quickly with a single struct.

## Disclaimer
This wrapper is intended for prototype development and reference only. Please use caution if you are considering using this code for production.
Currently this library uses OpenSSL with basic options only. Further updates will utilize more secure OpenSSL options.

## Limitations
LIBMISO clients can only comunicate with LIBMISO servers for the following reasons:
- LIBMISO sends and reads 3 bytes before the actual data, thus preventing reading plain data from other sources (such as webservers)
- LIBMISO data packet sizes are limited to SHORT (a size value of 2 bytes)
