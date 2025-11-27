cmake_minimum_required(VERSION 3.24)
project(xnet_tiny LANGUAGES C CXX) 

aux_source_directory(. DIR_HELLO_SRCS)
add_library(xnet_tiny  ${DIR_HELLO_SRCS} )
